# CMC

[![build](https://github.com/Fraunhofer-AISEC/cmc/actions/workflows/build.yml/badge.svg)](https://github.com/Fraunhofer-AISEC/cmc/actions/workflows/build.yml)
[![](https://godoc.org/github.com/Fraunhofer-AISEC/cmc?status.svg)](https://pkg.go.dev/github.com/Fraunhofer-AISEC/cmc)
[![Go Report Card](https://goreportcard.com/badge/github.com/Fraunhofer-AISEC/cmc)](https://goreportcard.com/report/github.com/Fraunhofer-AISEC/cmc)

The CMC repository provides software to enable remote attestation of computing platforms,
as well as secure attested TLS and HTTPS channels between those platforms. Currently, the CMC
repository supports Trusted Platform Modules (TPMs), AMD SEV-SNP, Intel SGX, as well as Intel TDX.
The goal is to make attestation easy for verifiers without prior knowledge of the peer's software
stack. This is achieved through a set of trusted CAs and self-contained attestation reports that
include signed metadata and reference hash values.

*A detailed description of the architecture can be found in our*
*[paper](https://dl.acm.org/doi/pdf/10.1145/3600160.3600171) and in the*
*[documentation](./doc)*

## Quick Start

> Note: If you want to run the *cmc* on actual hardware, refer to the [Setup](./doc/setup.md),
> [Build](./doc/build.md) and [Run](./doc/run.md) documentation.

For demonstration purposes only, we provide a docker container for building the software and a
Virtual Machine (VM) with attached software TPM.

If you choose to use the Docker container, simply ensure that
[Docker is installed](https://docs.docker.com/engine/install/). The container bind-mounts the
repository root directory and runs as the current user, meaning all artifacts are built in
the same location as they would be without Docker.

If you prefer not to use Docker, make sure all [prerequisites](./doc/setup.md#prerequisites) are
installed, and omit the `cmc-docker` prefix from each command.

Create and launch the VM with attached swTPM, establish server-side attested TLS connection to VM:
```sh
# Setup environment
source env.bash

# Download and configure image and tools
cmc-docker setup-vm

# Start swTPM (separate terminal )
cmc-docker vm-swtpm

# Start estserver
cmc-docker vm-estserver

# Start VM
cmc-docker vm-start

# Establish attested TLS connection to Ubuntu VM
cmc-docker vm-testtool
```

The [testtool](./doc/architecture.md#testtool) on the host establishes an attested TLS connection
to the testtool running within the ubuntu VM with server-side authentication and server-side
attestation. Find the generated attestation result in `cmc/data/attestation-result`.

> Note: This demo is not secure and attestation might fail. Refer to [VM Setup](./doc/setup-vm.md)
> for more information and how to fix.

## Further Documentation

The following contents can be found in the [doc](./doc/) folder:

### Architecture

An overview of the architecture is given in [Architecture](./doc/architecture.md).

### Setup

For detailed instructions on how to setup TPM, Intel SGX, Intel TDX or AMD SEV-SNP platforms
including PKI and metadata generation, refer to the [Setup Documentation](./doc/setup.md)

### Build

See [Build Documentation](./doc/build.md) for instructions on how to build the go binaries.

### Run

For configuring and running the go binaries, refer to the
[Run Documentation](./doc/configuration.md).

### APIs and Protocols

For a description of the `cmcd` gRPC, CoaP and socket APIs, refer to [CMCD API](./doc/cmcd-api.md).
For a description of the attested TLS attestation protocol, refer to
[Attestation Protocol](./doc/attestation-protocol.md).

### Integration

Usually, the attested TLS or HTTPS libraries are used within own projects to provide attestation
for TLS or HTTPS connections, as described in [Integration](./doc/go-integration.md)

### Additional Demo Setups

For an alternative demo setup with a more complex PKI and policies based on the requirements of
the International Data Spaces (IDS), see [IDS Example Setup](./doc/ids-example-setup.md)

