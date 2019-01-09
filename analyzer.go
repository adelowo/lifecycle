package lifecycle

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/pkg/errors"

	"github.com/buildpack/lifecycle/image"
)

type Analyzer struct {
	Buildpacks []*Buildpack
	AppDir     string
	LayersDir  string
	In         []byte
	Out, Err   *log.Logger
}

func (a *Analyzer) Analyze(image image.Image) error {
	found, err := image.Found()
	if err != nil {
		return err
	}

	var metadata AppImageMetadata
	if !found {
		a.Out.Printf("WARNING: image '%s' not found or requires authentication to access\n", image.Name())
	} else {
		metadata, err = a.getMetadata(image)
		if err != nil {
			return err
		}
	}
	return a.analyze(metadata)
}

func (a *Analyzer) analyze(metadata AppImageMetadata) error {
	groupBPs := a.buildpacks()

	err := a.removeOldBackpackLayersNotInGroup(groupBPs)
	if err != nil {
		return err
	}

	for groupBP := range groupBPs {
		cache, err := a.readCache(groupBP)
		analyzedDirectory := analyzedBuildPackDirectory{
			metadata:  metadata,
			layersDir: a.LayersDir,
			groupBP:   groupBP,
			cache:     cache,
		}
		layers, err := analyzedDirectory.allLayers()
		if err != nil {
			return err
		}

		for layer, layerData := range layers {
			cacheType := analyzedDirectory.classifyCache(layer)
			switch cacheType {
			case staleNoMetadata:
				a.Out.Printf("removing stale cached layer '%s/%s', not in metadata \n", groupBP, layer)
				if err := analyzedDirectory.removeLayer(layer); err != nil {
					return err
				}
			case staleWrongSHA:
				a.Out.Printf("removing stale cached launch layer '%s/%s'", groupBP, layer)
				if err := analyzedDirectory.removeLayer(layer); err != nil {
					return err
				}
			case nonLaunch:
				a.Out.Printf("using cached layer '%s/%s'", groupBP, layer)
			case valid:
				a.Out.Printf("using cached launch layer '%s/%s'", groupBP, layer)
			case noCache:
				if layerData
				a.Out.Printf("using cached launch layer '%s/%s'", groupBP, layer)
			}
		}

		for layer := range layers {
			layerType := analyzedDirectory.classifyLayer(layer)
			switch layerType {
			case launchNoCache:
				a.Out.Printf("writing metadata for layer '%s/%s'", groupBP, layer)

				if err := analyzedDirectory.restoreMetadata(layer); err != nil {
					return err
				}
			case launchBuildNoCache:
				a.Out.Printf("writing metadata for layer '%s/%s'", groupBP, layer)

				if err := analyzedDirectory.restoreMetadata(layer); err != nil {
					return err
				}
			case launchCached, launchBuildCached
				a.Out.Printf("using cached layer '%s/%s' ", groupBP, layer)
			}
		}
	}

	return nil
}

type analyzedBuildPackDirectory struct {
	metadata  AppImageMetadata
	layersDir string
	groupBP   string
	cache     map[string]*LayerMetadata
}

type layerType int

const (
	launchCached
	launchNoCache
	launchBuildCached
	launchBuildNoCache
)

func (abd *analyzedBuildPackDirectory) classifyLayer(layer string) layerType {
	cachedTOML, err := readTOML(abd.layerPath(layer) + ".toml")
	if err != nil {
		return noCacheLaunchLayer
	}

	buildpackMetadata, ok := bpMetadata(abd.groupBP, abd.metadata)
	if !ok {
		if !cachedTOML.Launch {
			return noMetaDataForBuildLayer
		} else {
			return noMetaDataForLaunchLayer
		}
	}

	layerMetadata, ok := buildpackMetadata.Layers[layer]
	if !ok {
		if !cachedTOML.Launch {
			return noMetaDataForBuildLayer
		} else {
			return noMetaDataForLaunchLayer
		}
	}

	sha, err := ioutil.ReadFile(abd.layerPath(layer + ".sha"))
	if err != nil {
		return noCacheLaunchLayer
	}

	if string(sha) != layerMetadata.SHA {
		if layerMetadata.Build {
			return outdatedBuildLayer
		} else {
			return outdatedLaunchLayer
		}
	}

	return existingCacheUptoDate
}

type cacheType int

const (
	staleNoMetadata cacheType = iota
	staleWrongSHA
	nonLaunch  //we can't determine whether the cache is stale for launch=false layers
	valid
	noCache
)

func (abd *analyzedBuildPackDirectory) classifyCache(name string) cacheType {
	cachedLayer, ok := abd.cache[name]
	if !ok {
		return noCache
	}
	if !cachedLayer.Launch {
		return nonLaunch
	}
	buildpackMetadata, ok := bpMetadata(abd.groupBP, abd.metadata)
	layerMetadata, ok := buildpackMetadata.Layers[name]
	if !ok {
		return staleNoMetadata
	}
	if layerMetadata.SHA != cachedLayer.SHA {
		return staleWrongSHA
	}
	return valid
}

func (a *Analyzer) readCache(bpID string) (map[string]*LayerMetadata, error) {
	cache := make(map[string]*LayerMetadata)
	tomls, err := filepath.Glob(filepath.Join(a.LayersDir, bpID, "*.toml"))
	if err != nil {
		return nil, err
	}
	for _, toml := range tomls {
		name := strings.TrimRight(filepath.Base(toml), ".toml")
		cache[name], _ = readTOML(toml)
		if sha, err := ioutil.ReadFile(filepath.Join(a.LayersDir, bpID, name+".sha")); err == nil {
			cache[name].SHA = string(sha)
		}
	}
	return cache, nil
}

func (abd *analyzedBuildPackDirectory) layerPath(layer string) string {
	return filepath.Join(abd.layersDir, abd.groupBP, layer)
}

func (abd *analyzedBuildPackDirectory) allLayers() (map[string]interface{}, error) {
	setOfLayers := make(map[string]interface{})
	buildpackMetadata, ok := bpMetadata(abd.groupBP, abd.metadata)
	if ok {
		for layer := range buildpackMetadata.Layers {
			setOfLayers[layer] = struct{}{}
		}
	}

	bpDir := filepath.Join(abd.layersDir, abd.groupBP)
	layerTOMLs, err := filepath.Glob(filepath.Join(bpDir, "*.toml"))
	if err != nil {
		return nil, err
	}
	for _, layerTOML := range layerTOMLs {
		name := strings.TrimRight(filepath.Base(layerTOML), ".toml")
		setOfLayers[name] = struct{}{}
	}
	return setOfLayers, nil
}

func (abd *analyzedBuildPackDirectory) restoreMetadata(layer string) error {
	buildpackMetadata, ok := bpMetadata(abd.groupBP, abd.metadata)
	if !ok {
		return fmt.Errorf("metadata unavailable for %s", layer)
	}

	layerMetadata, ok := buildpackMetadata.Layers[layer]
	if !ok {
		return fmt.Errorf("metadata unavailable for %s", layer)
	}

	return writeTOML(filepath.Join(abd.layersDir, abd.groupBP, layer+".toml"), layerMetadata)
}

func (abd *analyzedBuildPackDirectory) removeLayer(name string) error {
	if err := os.RemoveAll(abd.layerPath(name)); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Remove(abd.layerPath(name) + ".sha"); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Remove(abd.layerPath(name) + ".toml"); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func bpMetadata(groupBP string, metadata AppImageMetadata) (*BuildpackMetadata, bool) {
	for _, buildpackMetaData := range metadata.Buildpacks {
		if buildpackMetaData.ID == groupBP {
			return &buildpackMetaData, true
		}
	}

	return nil, false
}

func (a *Analyzer) getMetadata(image image.Image) (AppImageMetadata, error) {
	metadata := AppImageMetadata{}
	label, err := image.Label(MetadataLabel)
	if err != nil {
		return metadata, err
	}
	if label == "" {
		a.Out.Printf("WARNING: previous image '%s' does not have '%s' label", image.Name(), MetadataLabel)
		return metadata, nil
	}

	if err := json.Unmarshal([]byte(label), &metadata); err != nil {
		a.Out.Printf("WARNING: previous image '%s' has incompatible '%s' label\n", image.Name(), MetadataLabel)
		return metadata, nil
	}
	return metadata, nil
}

func (a *Analyzer) buildpacks() map[string]struct{} {
	buildpacks := make(map[string]struct{}, len(a.Buildpacks))
	for _, b := range a.Buildpacks {
		buildpacks[b.EscapedID()] = struct{}{}
	}
	return buildpacks
}

func (a *Analyzer) removeOldBackpackLayersNotInGroup(groupBPs map[string]struct{}) error {
	cachedBPs, err := a.cachedBuildpacks()
	if err != nil {
		return err
	}

	for _, cachedBP := range cachedBPs {
		_, exists := groupBPs[cachedBP]
		if !exists {
			a.Out.Printf("removing cached layers for buildpack '%s' not in group\n", cachedBP)
			if err := os.RemoveAll(filepath.Join(a.LayersDir, cachedBP)); err != nil && !os.IsNotExist(err) {
				return err
			}
		}
	}
	return nil
}

func (a *Analyzer) cachedBuildpacks() ([]string, error) {
	cachedBps := make([]string, 0, 0)
	bpDirs, err := filepath.Glob(filepath.Join(a.LayersDir, "*"))
	if err != nil {
		return nil, err
	}
	appDirInfo, err := os.Stat(a.AppDir)
	if err != nil && !os.IsNotExist(err) {
		return nil, errors.Wrap(err, "stat app dir")
	}
	for _, dir := range bpDirs {
		info, err := os.Stat(dir)
		if err != nil {
			return nil, err
		}
		if !os.SameFile(appDirInfo, info) && info.IsDir() {
			cachedBps = append(cachedBps, filepath.Base(dir))
		}
	}
	return cachedBps, nil
}

func writeTOML(path string, metadata LayerMetadata) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	fh, err := os.Create(path)
	if err != nil {
		return err
	}

	defer fh.Close()
	return toml.NewEncoder(fh).Encode(metadata)
}

func readTOML(path string) (*LayerMetadata, error) {
	var metadata LayerMetadata
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	_, err = toml.DecodeFile(path, &metadata)
	if err != nil {
		return nil, err
	}

	return &metadata, err
}
