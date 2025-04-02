# Build

All binaries can be built with the *go*-compiler.

> Note: Building SGX enclaves requires a custom compiler and different commands,
> see [SGX Setup](./setup-sgx.md)

## Build and Install all Binaries

```sh
# Clone the CMC repo
git clone https://github.com/Fraunhofer-AISEC/cmc

# Build CMC
cd cmc
go build ./...

# Install CMC $GOPATH/bin
go install ./...
```

## Build the Provisioning Server

```sh
cd est/estserver
go build
```

## Build the CMC Daemon

```sh
cd cmcd
go build
```

## Build the Test Tool

```sh
cd testtool
go build

# Build testtool as SGX enclave
make egocmc
```

## Customize Builds

### Reduce General Size

The size of all binaries can be reduced via go linker flags:
```sh
go build ldflags="-s -w"
```
For more information see the go documentation.

### Reduce Size by Disabling Features

The size of the binaries can further be reduced by a considerable amount through disabling
unused features during build time. The `go build` command builds each binary with all features
enabled. The project uses the go build system with build tags to disable features.

To disable all features, use the custom `nodefaults` tag. You can then enable the features you
want to build via additional tags.

Currently supported tags for the `cmcd` and `testtool` are:
- `nodefaults` Disables all features
- `grpc` Enables the gRPC API
- `coap` Enables the CoAP API
- `socket` Enables the socket API
- `libapi` Enables the library API
- `tpm` Enables the TPM driver
- `snp` Enables the SNP driver
- `tdx` Enables the Intel TDX driver
- `sgx` Enables the Intel SGX driver
- `sw` Enables the container driver

To build the cmcd/testtool with `socket` and `tpm` support:
```sh
go build -tags nodefaults,socket,tpm
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
