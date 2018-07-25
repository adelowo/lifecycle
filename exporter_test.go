package lifecycle_test

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/buildpack/lifecycle"
	"github.com/buildpack/packs/img"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/sclevine/spec"
	"github.com/sclevine/spec/report"
)

func TestExporter(t *testing.T) {
	rand.Seed(time.Now().UTC().UnixNano())
	spec.Run(t, "Exporter", testExporter, spec.Report(report.Terminal{}))
}

func testExporter(t *testing.T, when spec.G, it spec.S) {
	var (
		exporter       *lifecycle.Exporter
		stdout, stderr *bytes.Buffer
		tmpDir         string
	)

	it.Before(func() {
		stdout, stderr = &bytes.Buffer{}, &bytes.Buffer{}
		var err error
		tmpDir, err = ioutil.TempDir("", "pack.export.layer")
		if err != nil {
			t.Fatal(err)
		}
		exporter = &lifecycle.Exporter{
			TmpDir: tmpDir,
			Buildpacks: []lifecycle.Buildpack{
				{ID: "buildpack.id"},
			},
			Out: io.MultiWriter(stdout, it.Out()),
			Err: io.MultiWriter(stderr, it.Out()),
		}
	})
	it.After(func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			t.Fatal(err)
		}
	})

	when("#Export", func() {
		when("a simple launch dir exists", func() {
			var (
				stackImage v1.Image
			)
			it.Before(func() {
				var err error
				stackImage, err = GetBusyboxWithEntrypoint()
				if err != nil {
					t.Fatalf("get busybox image for stack: %s", err)
				}
			})

			it("sets toml files and layer digests labels", func() {
				image, err := exporter.Export("testdata/exporter/first/launch", stackImage, nil)
				if err != nil {
					t.Fatalf("Error: %s\n", err)
				}
				data, err := GetMetadata(image)
				if err != nil {
					t.Fatalf("Error: %s\n", err)
				}

				if !strings.HasPrefix(data.Stack.SHA, "sha256:") {
					t.Fatalf(`Matadata label '%s' did not have stack/sha with prefix 'sha256:'`, data.Stack.SHA)
				}
				if diff := cmp.Diff(data.Buildpacks[0].Layers["layer1"].Data, map[string]interface{}{"mykey": "myval"}); diff != "" {
					t.Fatalf(`Layer toml did not match: (-got +want)\n%s`, diff)
				}
			})

			it("sets app as layer", func() {
				image, err := exporter.Export("testdata/exporter/first/launch", stackImage, nil)
				if err != nil {
					t.Fatalf("Error: %s\n", err)
				}
				data, err := GetMetadata(image)
				if err != nil {
					t.Fatalf("Error: %s\n", err)
				}
				hash, err := v1.NewHash(data.App.SHA)
				if err != nil {
					t.Fatalf("Error: %s\n", err)
				}
				layer, err := image.LayerByDiffID(hash)
				if err != nil {
					t.Fatalf("Error: %s\n", err)
				}

				txt, err := GetLayerFile(layer, "launch/app/subdir/myfile.txt")
				if err != nil {
					t.Fatalf("Error: %s\n", err)
				}
				if strings.TrimSpace(txt) != "mycontents" {
					t.Fatalf(`app layer sample file contents: '%s' != 'mycontents'`, strings.TrimSpace(txt))
				}
			})

			it("sets buildpack/layer1 as layer", func() {
				image, err := exporter.Export("testdata/exporter/first/launch", stackImage, nil)
				if err != nil {
					t.Fatalf("Error: %s\n", err)
				}
				data, err := GetMetadata(image)
				if err != nil {
					t.Fatalf("Error: %s\n", err)
				}
				hash, err := v1.NewHash(data.Buildpacks[0].Layers["layer1"].SHA)
				if err != nil {
					t.Fatalf("Error: %s\n", err)
				}
				layer, err := image.LayerByDiffID(hash)
				if err != nil {
					t.Fatalf("Error: %s\n", err)
				}

				txt, err := GetLayerFile(layer, "launch/buildpack.id/layer1/file-from-layer-1")
				if err != nil {
					t.Fatalf("Error: %s\n", err)
				}
				if strings.TrimSpace(txt) != "echo text from layer 1" {
					t.Fatalf(`buildpack layer "layer1": sample file contents: '%s' != 'echo text from layer 1'`, strings.TrimSpace(txt))
				}
			})

			it("sets buildpack/layer2 as layer", func() {
				image, err := exporter.Export("testdata/exporter/first/launch", stackImage, nil)
				if err != nil {
					t.Fatalf("Error: %s\n", err)
				}
				data, err := GetMetadata(image)
				if err != nil {
					t.Fatalf("Error: %s\n", err)
				}
				hash, err := v1.NewHash(data.Buildpacks[0].Layers["layer2"].SHA)
				if err != nil {
					t.Fatalf("Error: %s\n", err)
				}
				layer, err := image.LayerByDiffID(hash)
				if err != nil {
					t.Fatalf("Error: %s\n", err)
				}

				txt, err := GetLayerFile(layer, "launch/buildpack.id/layer2/file-from-layer-2")
				if err != nil {
					t.Fatalf("Error: %s\n", err)
				}
				if strings.TrimSpace(txt) != "echo text from layer 2" {
					t.Fatalf(`buildpack layer "layer2": sample file contents: '%s' != 'echo text from layer 2'`, strings.TrimSpace(txt))
				}
			})

			// it("creates a runnable image", func() {
			// 	out, err := exec.Command("docker", "run", "-w", "/launch/app", imgName).CombinedOutput()
			// 	if err != nil {
			// 		t.Fatalf("Error: %s\n", err)
			// 	}
			//
			// 	if !strings.Contains(string(out), "text from layer 1") {
			// 		t.Fatalf(`Output "%s" did not contain "%s"`, string(out), "text from layer 1")
			// 	}
			// 	if !strings.Contains(string(out), "text from layer 2") {
			// 		t.Fatalf(`Output "%s" did not contain "%s"`, string(out), "text from layer 2")
			// 	}
			// 	if !strings.Contains(string(out), "Arg1 is 'MyArg'") {
			// 		t.Fatalf(`Output "%s" did not contain "%s"`, string(out), "Arg1 is 'MyArg'")
			// 	}
			// })

			// when("rebuilding when toml exists without directory", func() {
			// 	it.Before(func() {
			// 		if err := exporter.Export("testdata/exporter/second/launch", stackImage, repoStore); err != nil {
			// 			t.Fatalf("Error: %s\n", err)
			// 		}
			// 	})
			//
			// 	it("reuses layers if there is a layer.toml file", func() {
			// 		out, err := exec.Command("docker", "run", "-w", "/launch/app", imgName).CombinedOutput()
			// 		if err != nil {
			// 			fmt.Println(string(out))
			// 			t.Fatal(err)
			// 		}
			// 		if !strings.Contains(string(out), "text from layer 1") {
			// 			t.Fatalf(`Output "%s" did not contain "%s"`, string(out), "text from layer 1")
			// 		}
			// 		if !strings.Contains(string(out), "text from new layer 2") {
			// 			t.Fatalf(`Output "%s" did not contain "%s"`, string(out), "text from new layer 2")
			// 		}
			// 	})
			// })
		})
	}, spec.Parallel(), spec.Report(report.Terminal{}))
}

func GetBusyboxWithEntrypoint() (v1.Image, error) {
	stackStore, err := img.NewRegistry("busybox")
	if err != nil {
		return nil, fmt.Errorf("get store for busybox: %s", err)
	}
	stackImage, err := stackStore.Image()
	if err != nil {
		return nil, fmt.Errorf("get image for SCRATCH: %s", err)
	}
	configFile, err := stackImage.ConfigFile()
	if err != nil {
		return nil, err
	}
	config := *configFile.Config.DeepCopy()
	config.Entrypoint = []string{"sh", "-c"}
	return mutate.Config(stackImage, config)
}

func RandString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'a' + byte(rand.Intn(26))
	}
	return string(b)
}

func GetLayerFile(layer v1.Layer, path string) (string, error) {
	r, err := layer.Uncompressed()
	if err != nil {
		return "", err
	}
	defer r.Close()
	tr := tar.NewReader(r)

	for {
		header, err := tr.Next()
		if err != nil {
			return "", err
		}

		if header.Name == path {
			buf, err := ioutil.ReadAll(tr)
			return string(buf), err
		}
	}
	return "", fmt.Errorf("file not found: %s", path)
}

// func GetLayerFromImage(image v1.Image, keys ...string) {
// 	cfg, err := image.ConfigFile()
// 	if err != nil {
// 		t.Fatalf("Error: %s\n", err)
// 	}
// 	digest, err := jsonparser.GetString([]byte(cfg.Config.Labels["sh.packs.build"]), "app", "sha")
// 	if err != nil {
// 		t.Fatalf("Error: %s\n", err)
// 	}
// 	hash, err := v1.NewHash(digest)
// 	if err != nil {
// 		t.Fatalf("Error: %s\n", err)
// 	}
// 	layer, err := image.LayerByDiffID(hash)
// 	if err != nil {
// 		t.Fatalf("Error: %s\n", err)
// 	}
// }

type Metadata struct {
	Stack struct {
		SHA string `json:"sha"`
	} `json:"stack"`
	App struct {
		SHA string `json:"sha"`
	} `json:"app"`
	Buildpacks []struct {
		Key    string `json:"key"`
		Layers map[string]struct {
			SHA  string                 `json:"sha"`
			Data map[string]interface{} `json:"data"`
		} `json:"layers"`
	} `json:"buildpacks"`
}

func GetMetadata(image v1.Image) (Metadata, error) {
	var metadata Metadata
	cfg, err := image.ConfigFile()
	if err != nil {
		return metadata, fmt.Errorf("read config: %s", err)
	}
	label := cfg.Config.Labels["sh.packs.build"]
	if err := json.Unmarshal([]byte(label), &metadata); err != nil {
		return metadata, fmt.Errorf("unmarshal: %s", err)
	}
	return metadata, nil
}
