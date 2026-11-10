# Build

All binaries can be built with the [*go*-toolchain](https://go.dev/doc/install).

> Note: Building SGX enclaves requires a custom compiler and different commands,
> see [SGX Setup](./setup-sgx.md)

## Build and Install

The top-level Makefile builds the binaries into `build/` and installs them together with their
default configuration files and systemd units. The binaries are grouped into components:

| Component | Binaries                                                | systemd units                             |
| --------- | ------------------------------------------------------- | ----------------------------------------- |
| device    | `cmcd`, `cmcctl`                                        | `cmcd.service`                            |
| infra     | `estserver`, `cmcbackend`                               | `estserver.service`, `cmcbackend.service` |
| tools     | `metatool`, `mrtool`, `snptool`, `tdxtool`, `azuretool` |                                           |
| caddy     | `caddy-atls`                                            | `caddy-atls.service`                      |

```sh
# Clone the CMC repo
git clone https://github.com/Fraunhofer-AISEC/cmc
cd cmc

# Build the device component, or make build-infra, make build-tools, make build-caddy,
# make build-all
make

# Install the device component system-wide, or make install-infra, make install-tools,
# make install-caddy, make install-all
sudo make install
```

This installs to the following locations, depending on whether `make install` run as root:

|               | `sudo make install`             | `make install`           |
| ------------- | ------------------------------- | ------------------------ |
| Binaries      | `/usr/local/bin`                | `~/.local/bin`           |
| Configs       | `/etc/cmc`                      | `~/.config/cmc`          |
| systemd units | `/usr/local/lib/systemd/system` | `~/.config/systemd/user` |

`PREFIX`, `BINDIR`, `UNITDIR` and `DESTDIR` can be overridden. The configs are generated with
`<binary> config init`, the Caddy config `caddy-atls.caddyfile` from a reverse proxy template.
Existing configs are kept. Site-specific settings such as the EST server, root CAs and metadata
locations must be adjusted before starting the services:

```sh
sudo vim /etc/cmc/cmcd.toml # Adjust to your needs
sudo systemctl enable --now cmcd
```

The uninstall targets (`uninstall`, `uninstall-infra`, `uninstall-tools`, `uninstall-caddy`,
`uninstall-all`) remove binaries and units, but keep configs and data.

The binaries can also be built and installed with the go toolchain only, without configs and units:
```sh
go install ./...
```

## Customize Builds

### Reduce General Size

The size of all binaries can be reduced via go linker flags, which the Makefile uses by default:
```sh
go build -ldflags="-s -w"
```
For more information see the go documentation.

### Reduce Size by Disabling Features

The size of the binaries can further be reduced by a considerable amount through disabling
unused features during build time. The `go build` command builds each binary with all features
enabled. The project uses the go build system with build tags to disable features.

To disable all features, use the custom `nodefaults` tag. You can then enable the features you
want to build via additional tags.

Currently supported tags for the `cmcd` and `cmcctl` are:
- `nodefaults` Disables all features
- `grpc` Enables the gRPC API
- `socket` Enables the socket API
- `libapi` Enables the library API
- `tpm` Enables the TPM driver
- `snp` Enables the SNP driver
- `tdx` Enables the Intel TDX driver
- `sgx` Enables the Intel SGX driver
- `sw` Enables the container driver

To build the cmcd/cmcctl with `socket` and `tpm` support:
```sh
go build -tags nodefaults,socket,tpm

# Or via the Makefile
make TAGS=nodefaults,socket,tpm
```

> Note: disabling features during build-time but specifying to use them in the configuration files
> will lead to errors during runtime

### Regenerate Protobuf gRPC Interface

see: https://grpc.io/docs/languages/go/quickstart/ for newer versions

```sh
sudo apt install -y protobuf-compiler
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2
cd grpcapi/
make
```
