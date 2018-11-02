package lifecycle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/buildpack/lifecycle/img"
	"github.com/docker/docker/pkg/archive"
	"github.com/docker/docker/pkg/idtools"
	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/pkg/errors"
)

type Exporter struct {
	Buildpacks []*Buildpack
	TmpDir     string
	In         []byte
	Out, Err   io.Writer
	UID, GID   int
}

func (e *Exporter) Export(launchDirSrc, launchDirDst string, runImage, origImage v1.Image) (v1.Image, error) {
	dir, err := e.Stage1(launchDirSrc, launchDirDst)
	if err != nil {
		return nil, err
	}
	return e.Stage2(dir, launchDirDst, runImage, origImage)
}

// TODO: Convert from input having runImage as v1.Image and instead pass in run image metadata and
//       previous metadata. This means the metadata.json is now fully baked
func (e *Exporter) Stage1(launchDirSrc, launchDirDst string) (string, error) {
	var err error
	var metadata AppImageMetadata

	metadata.App.SHA, err = e.exportTar(launchDirSrc, launchDirDst, "app")
	if err != nil {
		return "", err
	}
	metadata.Config.SHA, err = e.exportTar(launchDirSrc, launchDirDst, "config")
	if err != nil {
		return "", err
	}

	for _, buildpack := range e.Buildpacks {
		bpMetadata := BuildpackMetadata{ID: buildpack.ID, Version: buildpack.Version, Layers: make(map[string]LayerMetadata)}
		layers, err := filepath.Glob(filepath.Join(launchDirSrc, buildpack.ID, "*.toml"))
		if err != nil {
			return "", err
		}
		for _, layer := range layers {
			var bpLayer LayerMetadata
			if filepath.Base(layer) == "launch.toml" {
				continue
			}
			dir := strings.TrimSuffix(layer, ".toml")
			layerName := filepath.Base(dir)
			_, err := os.Stat(dir)
			if !os.IsNotExist(err) {
				bpLayer.SHA, err = e.exportTar(launchDirSrc, launchDirDst, filepath.Join(buildpack.ID, layerName))
				if err != nil {
					return "", err
				}
			}
			var tomlData map[string]interface{}
			if _, err := toml.DecodeFile(layer, &tomlData); err != nil {
				return "", errors.Wrap(err, "read layer TOML data")
			}
			bpLayer.Data = tomlData
			bpMetadata.Layers[layerName] = bpLayer
		}
		metadata.Buildpacks = append(metadata.Buildpacks, bpMetadata)
	}

	data, err := json.Marshal(metadata)
	if err != nil {
		return "", err
	}
	err = ioutil.WriteFile(filepath.Join(e.TmpDir, "metadata.json"), data, 0600)
	if err != nil {
		return "", err
	}

	return e.TmpDir, nil
}

func rawSHA(prefixedSHA string) string {
	return strings.TrimPrefix(prefixedSHA, "sha256:")
}

func (e *Exporter) Stage2(exportDir, launchDirDst string, runImage, origImage v1.Image) (v1.Image, error) {
	data, err := ioutil.ReadFile(filepath.Join(exportDir, "metadata.json"))
	if err != nil {
		return nil, err
	}

	var metadata AppImageMetadata
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, err
	}
	if err := addRunImageMetadata(runImage, &metadata); err != nil {
		return nil, err
	}

	repoImage, _, err := img.Append(runImage, filepath.Join(exportDir, fmt.Sprintf("%s.tar", rawSHA(metadata.App.SHA))))
	if err != nil {
		return nil, errors.Wrap(err, "append app layer")
	}
	repoImage, _, err = img.Append(repoImage, filepath.Join(exportDir, fmt.Sprintf("%s.tar", rawSHA(metadata.Config.SHA))))
	if err != nil {
		return nil, errors.Wrap(err, "append config layer")
	}

	var origMetadata *AppImageMetadata
	if origImage != nil {
		origMetadata, err = e.GetMetadata(origImage)
		if err != nil {
			return nil, errors.Wrap(err, "find metadata")
		}
	}

	for _, bpMetadata := range metadata.Buildpacks {
		fmt.Println("BPM: ", bpMetadata)
		for layerName, data := range bpMetadata.Layers {
			tar := filepath.Join(exportDir, fmt.Sprintf("%s.tar", rawSHA(data.SHA)))
			fmt.Println("TAR: ", layerName, tar)
			_, err := os.Stat(tar)
			if os.IsNotExist(err) {
				data.SHA, err = origLayerDiffID(origMetadata, bpMetadata.ID, layerName)
				if err != nil {
					return nil, err
				}
				hash, err := v1.NewHash(data.SHA)
				topLayer, err := origImage.LayerByDiffID(hash)
				if err != nil {
					return nil, errors.Wrapf(err, "find previous layer %s/%s", bpMetadata.ID, layerName)
				}
				repoImage, err = mutate.AppendLayers(repoImage, topLayer)
				if err != nil {
					return nil, errors.Wrapf(err, "append layer %s/%s from previous image", bpMetadata.ID, layerName)
				}
				bpMetadata.Layers[layerName] = data
			} else {
				repoImage, _, err = img.Append(repoImage, tar)
				if err != nil {
					return nil, errors.Wrapf(err, "append new layer %s/%s", bpMetadata.ID, layerName)
				}
			}
		}
	}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return nil, errors.Wrap(err, "get encoded metadata")
	}
	repoImage, err = img.Label(repoImage, MetadataLabel, string(metadataJSON))
	if err != nil {
		return nil, errors.Wrap(err, "set metadata label")
	}

	repoImage, err = img.Env(repoImage, EnvLaunchDir, launchDirDst)
	if err != nil {
		return nil, errors.Wrap(err, "set launch dir env var")
	}

	return repoImage, nil
}

func origLayerDiffID(metadata *AppImageMetadata, buildpackID, layerName string) (string, error) {
	if metadata == nil {
		return "", fmt.Errorf("cannot reuse layer, missing previous image metadata")
	}
	for _, buildpack := range metadata.Buildpacks {
		if buildpack.ID == buildpackID {
			data, ok := buildpack.Layers[layerName]
			if !ok {
				return "", fmt.Errorf("previous image has no layer '%s/%s'", buildpackID, layerName)
			}
			return data.SHA, nil
		}
	}
	return "", fmt.Errorf("cannot reuse layer '%s/%s', previous image has no layers for buildpack '%s'", buildpackID, layerName, buildpackID)
}

func addRunImageMetadata(runImage v1.Image, metadata *AppImageMetadata) error {
	runLayerDiffID, err := img.TopLayerDiffID(runImage)
	if err != nil {
		return errors.Wrap(err, "find run image digest")
	}
	runImageDigest, err := runImage.Digest()
	if err != nil {
		return errors.Wrap(err, "find run image digest")
	}
	metadata.RunImage = RunImageMetadata{
		TopLayer: runLayerDiffID.String(),
		SHA:      runImageDigest.String(),
	}
	return nil
}

func (e *Exporter) GetMetadata(image v1.Image) (*AppImageMetadata, error) {
	var metadata *AppImageMetadata
	cfg, err := image.ConfigFile()
	if err != nil {
		return metadata, err
	}
	label := cfg.Config.Labels[MetadataLabel]
	if err := json.Unmarshal([]byte(label), &metadata); err != nil {
		return metadata, err
	}
	return metadata, nil
}

func (e *Exporter) writeWithSHA(r io.Reader) (string, error) {
	hasher := sha256.New()

	f, err := ioutil.TempFile(e.TmpDir, "tarfile")
	if err != nil {
		return "", err
	}
	defer f.Close()

	w := io.MultiWriter(hasher, f)

	if _, err := io.Copy(w, r); err != nil {
		return "", err
	}

	sha := hex.EncodeToString(hasher.Sum(make([]byte, 0, hasher.Size())))

	if err := f.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(f.Name(), filepath.Join(e.TmpDir, sha+".tar")); err != nil {
		return "", err
	}

	return "sha256:" + sha, nil
}

func (e *Exporter) exportTar(launchDirSrc, launchDirDst, name string) (string, error) {
	tarOptions := &archive.TarOptions{
		IncludeFiles: []string{name},
		RebaseNames: map[string]string{
			name: launchDirDst + "/" + name,
		},
	}
	if e.UID > 0 && e.GID > 0 {
		tarOptions.ChownOpts = &idtools.Identity{
			UID: e.UID,
			GID: e.GID,
		}
	}
	rc, err := archive.TarWithOptions(filepath.Join(launchDirSrc), tarOptions)
	if err != nil {
		return "", err
	}
	defer rc.Close()
	return e.writeWithSHA(rc)
}
