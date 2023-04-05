# CMC

[![build](https://github.com/Fraunhofer-AISEC/cmc/actions/workflows/build.yml/badge.svg)](https://github.com/Fraunhofer-AISEC/cmc/actions/workflows/build.yml)
[![](https://godoc.org/github.com/Fraunhofer-AISEC/cmc?status.svg)](https://pkg.go.dev/github.com/Fraunhofer-AISEC/cmc)
[![Go Report Card](https://goreportcard.com/badge/github.com/Fraunhofer-AISEC/cmc)](https://goreportcard.com/report/github.com/Fraunhofer-AISEC/cmc)

The CMC repository provides tools and software to enable remote attestation of computing platforms,
as well as remote attested TLS channels between those platforms. Currently, the CMC repository
supports Trusted Platform Module (TPM) as well as AMD SEV-SNP attestation.

- [CMC](#cmc)
  - [Architecture Overview](#architecture-overview)
  - [Basic Principle](#basic-principle)
  - [Prerequistes](#prerequistes)
  - [Quick Demo Setup](#quick-demo-setup)
  - [Run the CMC](#run-the-cmc)
    - [Establish an attested TLS connection](#establish-an-attested-tls-connection)
  - [Configuration](#configuration)
    - [CMCD Configuration](#cmcd-configuration)
    - [EST Server Configuration](#est-server-configuration)
  - [Testtool Configuration](#testtool-configuration)
    - [Platform Configuration](#platform-configuration)
  - [Custom Policies](#custom-policies)
  - [Build](#build)
    - [Build and Run the Provisioning Server](#build-and-run-the-provisioning-server)
    - [Build and Run the CMC Daemon](#build-and-run-the-cmc-daemon)
    - [Build and Run the Test Tool](#build-and-run-the-test-tool)
    - [Customize Builds](#customize-builds)
      - [Reduce General Size](#reduce-general-size)
      - [Reduce Size by Disabling Features](#reduce-size-by-disabling-features)
      - [Regenerate Protobuf gRPC Interface](#regenerate-protobuf-grpc-interface)

## Architecture Overview

![CMC, drivers and exemplary testtool as well as interface descriptions](./doc/overview.drawio.svg)

The figure shows how the core components interact with each other. The main software components are:
- The *cmcd* daemon acts as an attestation prover and verifier: It collects measurements from
different hardware trust anchors and assembles this data together with signed metadata describing
the platform to an attestation report (prover), or validates the measurements against the metadata.
The *cmcd* provides a gRPC as well as a CoAP REST API.
- The testtool is an exemplary application that make use of the *cmcd* to
generate and verify attestation reports and to create an attested tls connections.
- Drivers for trusted hardware provides the attestation reports and, if available, key storage and
signing functionalities

Refer to the [Architecture](doc/Architecture.md) Readme for more information.

## Basic Principle

The overall exchanged data structure *Attestation Report* does not only contain measurements of
the software running on the platform, but also metadata in the form of *Manifests* and
*Descriptions*. This metadata describes the entire state of the platform and must be signed by
one or more trusted entities. This allows a verifier to validate the attestation report without
knowing the platform in advance. Examples and tools for creating the metadata on the prover side
are given below.

## Prerequistes

- Running the *cmcd* currently requires a Linux platform. If the *cmcd* is configured to use a TPM,
the *cmcd* must be able to access ```/dev/tpm0```. If AMD SEV-SNP is
used for measurements, the *cmcd* must be run on an AMD server within an SNP Virtual Machine.
- Building the *cmcd* requires *go* (https://golang.org/doc/install)

**Note**: If configured to be used with a TPM, The *cmcd* accesses the TPM and creates keys within
the TPM. You should not run it on your normal work laptop, as it might require the TPM and its keys
storage for secure boot, disk encryption or other purposes. Instead, run it on a dedicated
Virtual Machine (VM) or server.

## Quick Demo Setup

The CMC repository contains a complete local example setup including a demo CA and all required
configurations and metadata. It was tested on Ubuntu 22.04 LTS.

> :warning: **Note:** You should run this only for testing on a development machine

```sh
git clone https://github.com/Fraunhofer-AISEC/cmc.git
./cmc/example-setup/setup-full-simple <cmc-folder> <metadata-folder>
```
with `<cmc-folder>` as the relative or absolute path to the cloned `cmc` repository and
`<metadata-folder>` as an arbitrary folder where metadata and configuration files are stored.

*For an alternative demo setup with a more complex PKI and policies based on the requirements of the International Data Spaces (IDS), see [IDS Example Setup](./doc/ids-example-setup.md)*

**For instructions on creating and signing the metadata with an arbitrary PKI yourself,**
**see [Manual Setup](./doc/manual-setup.md)**

## Run the CMC

```sh
# Start the EST server that supplies the certificates and metadata for the cmcd
server -config $CMC_ROOT/cmc-data/est-server-conf.json

# Build and run the cmcd
cmcd -config $CMC_ROOT/cmc-data/cmcd-conf.json

# Run the testtool to retrieve an attestation report (stored in current folder unless otherwise specified)
testtool -mode generate

# Run the testtool to verify the attestation report (stored in current folder unless otherwise specified)
testtool -mode verify -ca $CMC_ROOT/cmc-data/pki/ca.pem
```

### Establish an attested TLS connection

```sh
# Run an attested TLS server
testtool -mode listen -addr 0.0.0.0:4443 -ca $CMC_ROOT/cmc-data/pki/ca.pem -mtls

# Run an attested TLS client estblishing a mutually attested TLS connection to the server
testtool -mode dial -addr localhost:4443 -ca $CMC_ROOT/cmc-data/pki/ca.pem -mtls
```

**Note**: The *cmcd* TPM provisioning process includes the verification of the TPM's EK certificate
chain. In the example setup, this verification is turned off, as the database might not contain
the certificate chain for the TPM of the machine the *cmcd* is running on. Instead, simply a
warning is printed. The intermediate and root CA for this chain can be downloaded from the TPM
vendor. The certificates can then be added in to the ```cmc/example-setup/tpm-ek-certs.db```
database. The ```verifyEkCert``` parameter in the *provserver* config can then be set to true.

## Configuration

All binaries can be configured via JSON configuration files and commandline flags. If a
configuration option is specified both via configuration file and commandline flag, the
commandline flag supersedes.

The commandline flags can be shown via `<binary> -help`. Exemplary JSON configuration file examples
can be found in the `examples/` folder of this repository. Paths in the configuration files can
either be absolute, or relative to the path of the configuration file or the binary.

The remainder of this section explains the different options.

### CMCD Configuration

- **addr**: The address the *cmcd* should listen on, e.g. 127.0.0.1:9955
- **provServerAddr**: The URL of the provisioning server. The server issues certificates for the
TPM or software keys. In case of the TPM, the TPM *Credential Activation* process is performed.
- **metadataAddr**: The URL of the metadata server to retrieve the metadata from.
- **localPath**: the local path to store the meta-data and internal files. In a local setup, all
manifests and descriptions must be placed in this folder. If the provisioning server is used for
the meta-data (*cmcd* command line argument *-fetch-metadata*), the *cmcd* will store those files
in this folder. In this case, it is not required that the folder already exists, the *cmcd* will
handle everything automatically
- **fetchMetadata**: Boolean to specify whether the *cmcd* should load/update its metadata from
the provisioning server. If set to false, the *cmcd* expects all files to be present in the
*localPath*
- **drivers**: Tells the *cmcd* prover which drivers to use, currently
supported are `TPM`, `SNP`, and `SW`. If multiple drivers are used for measurements, always the
first provided driver is used for signing operations
- **useIma**: Bool that indicates whether the Integrity Measurement Architecture (IMA) shall be used
- **imaPcr**: TPM PCR where the IMA measurements are recorded (must match the kernel
configuration). The linux kernel default is 10
- **keyConfig**: The algorithm to be used for the *cmcd* keys. Possible values are:  RSA2048,
RSA4096, EC256, EC384, EC521
- **serialization**: The serialiazation format to use for the attestation report. Can be either
`cbor` or `json`
- **api**: Selects whether to use the `grpc`, `coap`, or `socket` API
- **network**: Only relevant for the `socket` API, selects whether to use `TCP` or
`Unix Domain Sockets`
- **logLevel**: The logging level. Possible are trace, debug, info, warn, and error.

### EST Server Configuration

- **port**: The port the server should listen on
- **signingKey**: The private key of the CA used to sign the device certificates.
- **signingCerts**: The certificate chain of the CA used to sign the device certificates.
- **httpFolder**: The root folder containing metadata (manifests and descriptions) that is served
by the provisioning server to be fetched by the `cmcd`
- **verifyEkCert**: Boolean, specifies if the EK certificate chain should be validated via the
**tpmEkCertDb**
- **tpmEkCertDb**: SQLite database containing intermediate CA and CA certificates from the TPM
manufacturers. The provisioning server uses these certificates to verify the TPM
Endorsement Key (EK) certificate. The repository contains an example database with the
certificates of some TPM manufacturers which can be used. For different manufacturers,
certificates might need to be added.
- **vcekOfflineCaching**: Boolean, specifies whether AMD SEV-SNP VCEK certificates downloaded from
the AMD KDS server should be stored locally for later offline retrieval
- **vcekCacheFolder**: The folder the downloaded VCEK certificates should locally be stored (only
relevant if vcekOfflineCaching is set to true)
- **estKey**: Server private key for establishing HTTPS connections
- **estCerts**: Server certificate chain(s) for establishing HTTPS connections
- **logLevel**: The logging level. Possible are trace, debug, info, warn, and error.

## Testtool Configuration

- **mode**: The mode to run. Possible are generate, verify, dial, listen, cacerts and iothub
- **addr**: The address to serve in mode listen, and to connect to in mode dial
- **cmc**: The address of the CMC server
- **report**: The file to store the attestation report in (mode generate) or to retrieve
from (mode verify)
- **result**: The file to store the attestation result in (mode verify)
- **nonce**: The file to store the nonce in (mode generate) or to retrieve from (mode verify)
- **ca**: The trust anchor CA(s)
- **policies**: Optional policies files
- **mtls**: Perform mutual TLS in mode dial and listen
- **api**: Selects whether to use the `grpc`, `coap`, or `socket` API
- **network**: Only relevant for the `socket` API, selects whether to use `TCP` or
`Unix Domain Sockets`
- **logLevel**: The logging level. Possible are trace, debug, info, warn, and error.

**The testtool can run the following commands/modes:**
- **cacerts**: Retrieves the CA certificates from the EST server
- **generate**: Generates an attestation report and stores it under the specified path
- **verify**: Verifies a previously generated attestation report
- **dial**: Run attestedTLS client application
- **listen**: Serve as a attestedTLS echo server

### Platform Configuration

The *cmcd* does not provide platform security itself, it only allows to make verifiable claims
about the software running on a platform. Thus, a secure base plaftorm is essential for the
overall security of the platform. This includes the kernel configuration, OS configuration,
file systems and software running on the host. Some configurations are mandatory for the *cmcd*
to work (e.g., if used, TPM-support must be enabled in the kernel configuration).

Further information about the platform configuration can be found
[here](doc/platform-configuration.md)

## Custom Policies

The basic validation verifies all signatures, certificate chains and reference values against the
measurements. To enable custom policies, such as the verification of certain certificate properties,
the blacklisting of certain software artifacts with known vulnerabilities or the enforcement of a
four eyes principle mandating different PKIs for the manifests, the attestation report module
implements a generic policies interface.

The current implementation contains the `attestationpolicies` module which implements a javascript
engine. This allows passing arbitrary javascript files via the `testtool` `-policies` parameter.
The policies javascript file is then used to evaluate arbitrary attributes of the JSON
attestation result output by the `cmcd` and stored by the `testtool`. The attestation result
can be referenced via the `json` variable in the script. The javascript code must return a single
boolean indicating success or failure of the custom policy validation. A minimal policies file, verifying only the `type` field of the attesation result could look as follows:

```js
// Parse the verification result
var obj = JSON.parse(json);
var success = true;

// Check the type field of the verification result
if (obj.type != "Verification Result") {
    console.log("Invalid type");
    success = false;
}

success
```

## Build

All binaries can be built with the *go*-compiler. For an explanation of the various flags run
<binary> -help

### Build and Run the Provisioning Server

```sh
cd provserver
go build
./provserver -help # For all commandline flags
```

### Build and Run the CMC Daemon

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

### Build and Run the Test Tool

```sh
cd testtool
go build
./testtool -help # To display all commandline options
```

### Customize Builds

#### Reduce General Size

The size of all binaries can be reduced via go linker flags:
```sh
go build ldflags="-s -w"
```
For more information see the go documentation.

#### Reduce Size by Disabling Features

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

#### Regenerate Protobuf gRPC Interface

see: https://grpc.io/docs/languages/go/quickstart/ for newer versions

```sh
sudo apt install -y protobuf-compiler
go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.28
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.2
cd grpcapi/
make
```
