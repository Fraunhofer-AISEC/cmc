# Containerd Container Measurements

## Prerequisites and Build

### Containerd Configuration
To measure containers, we require the `containerd-shim-cmc-v1` proxy shim, to be invoked by
containerd instead of the default shim `containerd-shim-runc-v2`. The proxy shim measures the
container and then invokes `containerd-shim-runc-v2`.

#### Alternative 1

Add the following to `/etc/containerd/config.toml`
```
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.cmc]
  runtime_type = "io.containerd.runtime.v1.linux"
  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.cmc.options]
    BinaryName = "/usr/bin/containerd-shim-cmc-v1"
```

Restart containerd:
```sh
sudo systemctl restart containerd
```

The shim can now be invoked with the following `ctr` argument:
`--runtime io.containerd.runtime.v1.linux.cmc`

#### Alternative 2

If an absolute path is used, no containerd configuration changes are required:
`--runtime /path/to/cmc/tools/containerd-shim-cmc-v1/containerd-shim-cmc-v1`

### Build the CMC

build all CMC binaries according to the README, especially
`cmc/tools/containerd-shim-cmc-v1/containerd-shim-cmc-v1` (can be built via `go build`). If
*Alternative 1* was chosen, the binary must be copied to `/usr/bin`.

### Run the CMC

Make sure the `cmcd` and `estserver` are running (see main README.md)


### Create Reference Values for Containers to be Executed

#### Alternative 1: Perform containerd dry run with good reference container and collect reference values

**Note**: The
[example-setup/update-container-manifest-live](../../example-setup/update-container-manifest-live)
script can be used to generate a manifest for a specific container. The following manual setup
explains the single steps.


To do a "dry run" of the custom shim to generate the reference values for a trusted container, pull the image:
```bash
ctr image pull docker.io/library/ubuntu:22.04
```

And then generate the reference values:
```bash
sudo ctr run --runtime io.containerd.runtime.v1.linux.cmc -env VAL=HELLO -t --rm docker.io/library/ubuntu:22.04 CMC_GENERATE_APP_MANIFEST
```

This will create reference values for the container and store it in `/tmp/measure/container-refs`

Generate CMC metadata as described in the CMC Readme, generate an app manifest and add the reference values.

Sign this manifest and add it to `cmc-data`:
```sh
cmc-signing-tool -in /tmp/measure/app.manifest.json   -out metadata-signed/app.manifest.json    -keys pki/signing-cert-key.pem -x5cs pki/signing-cert.pem,pki/ca.pem
```

#### Alternative 2: Use tools to convert OCI image to runtime bundle and measure reference values

This requires `buildah` and `umoci` to be installed: `sudo apt install buildah umoci`

**Note**: The
[example-setup/update-container-manifest](../../example-setup/update-container-manifest)
script can be used to generate a manifest for a specific container. The following manual setup
explains the single steps.

```sh
buildah pull <container-image>
buildah push <container-image> oci-archive:myimage-oci.tar
```

Extract the OCI image:
```sh
tar -xvf myimage-oci.tar
```

Unpack the image to a bundle:
```sh
umoci unpack --rootless --image ./ bundle
```

Measure runtime bundle:
```sh
./measure-bundle -config bundle/config.json -rootfs bundle/rootfs
```

Now create an app manifest and add the reference values as described in *Alternative 1*

## Run a container

Now, run the container:
```bash
sudo ctr run --runtime io.containerd.runtime.v1.linux.cmc -env VAL=HELLO -t --rm docker.io/library/ubuntu:22.04 my_container
```

The container will always start, but changing e.g. the environment variable will lead to a failed remote attestation.

## Logging and Troubleshooting

- If managed by systemd, the containerd logs can be retrieved via: `journalctl -u containerd`
- To get more detailed containerd logs: `containerd -log-level trace`
- The `containerd-shim-cmc-v1` logs are located at: `/tmp/containerd-shim-cmc.log`
- The original shim logs are retrieved by containerd / the proxy shim
