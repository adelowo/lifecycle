# Buildpack v3 reference implementation

## Building

Build the images:

```sh-session
$ bin/build
```

## Usage

Create your `workspace` dir:

```sh-session
$ cd /tmp
$ mkdir workspace
$ cp -R /path/to/your/app workspace/app
```

Create a volume for the cache:

```sh-session
$ docker volume create --name packs_cache
```

Detect:

```sh-session
$ docker run --rm -v "$(pwd)/workspace:/workspace" packs/samples /lifecycle/detector
```

Analyze:

```sh-session
$ docker run --rm -v "$(pwd)/workspace:/workspace" packs/build /lifecycle/analyzer
```

Build:

```sh-session
$ docker run --rm -v "$(pwd)/workspace:/workspace" -v "packs_cache:/cache" packs/samples /lifecycle/builder
```

Run:

```sh-session
$ docker run --rm -P -v "$(pwd)/workspace:/workspace" packs/run
```

Export:

```sh-session
$ docker run --rm -v "$(pwd)/workspace:/workspace" -e PACK_RUN_IMAGE="packs/run" \
  packs/build /lifecycle/exporter myimage
```