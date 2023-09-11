# Build

All binaries can be built with the *go*-compiler. For an explanation of the various flags run
<binary> -help

## Build and Run the Provisioning Server

```sh
cd est/estserver
go build
./estserver -help # For all commandline flags
```

## Build and Run the CMC Daemon

The below commands show how to build and run the cmcd. At runtime, a client can provide the cmcd
with root certificates that are to be used during the verification of the attestation report. If
these are not provided, the cmcd uses the system's root certificates instead. Under Linux, these are
commonly stored under `/etc/ssl/certs`. To temporarily add certificates, see the commands
using `SSL_CERT_FILE` and `SSL_CERT_DIR` below.

```sh
cd cmcd
go build
./cmcd -help # For all command line options
# with added custom certificates
SSL_CERT_FILE=../example-setup/pki/ca/ca.pem ./cmcd -config <config-file>
SSL_CERT_DIR=../example-setup/pki/ca/ ./cmcd -config <config-file>
```

## Build and Run the Test Tool

```sh
cd testtool
go build
./testtool -help # To display all commandline options
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
- `grpc` Enables the gRPC API
- `coap` Enables the CoAP API

To build all binaries with `coap` but without `grpc` support:
```sh
go build -tags nodefaults,coap
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