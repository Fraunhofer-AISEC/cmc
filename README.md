# CMC

[![build](https://github.com/Fraunhofer-AISEC/cmc/actions/workflows/build.yml/badge.svg)](https://github.com/Fraunhofer-AISEC/cmc/actions/workflows/build.yml)
[![](https://godoc.org/github.com/Fraunhofer-AISEC/cmc?status.svg)](https://pkg.go.dev/github.com/Fraunhofer-AISEC/cmc)
[![Go Report Card](https://goreportcard.com/badge/github.com/Fraunhofer-AISEC/cmc)](https://goreportcard.com/report/github.com/Fraunhofer-AISEC/cmc)

The CMC repository provides tools and software to enable remote attestation of computing platforms,
as well as remote attested TLS and HTTPS channels between those platforms. Currently, the CMC
repository supports Trusted Platform Modules (TPMs), AMD SEV-SNP, Intel SGX as well as Intel TDX.
The goal is to make attestation easy for verifiers without prior knowledge of the software stack,
based on a set of trusted CAs and signed metadata describing the software stack.

*A detailed description of the architecture can be found in our*
*[paper](https://dl.acm.org/doi/pdf/10.1145/3600160.3600171) and in the*
*[documentation](./doc)*

## Quick Start

### Prerequites

Make sure, all [prerequisites](./doc/setup.md#prerequisites) are installed and all
[requirements](./doc/setup.md#requirements) are met.

### Build

Clone the repository:
```sh
git clone https://github.com/Fraunhofer-AISEC/cmc.git
```

Build and install all tools to `$HOME/go/bin`:
```sh
cd cmc
go build ./...
go install ./...
```

Instructions on how to customize the build can be found in the [Build Documentation](./doc/build.md).

### Run

We provide a Ubuntu-VM with attached swTPM for testing:
```sh
source env.bash

# Download and configure image and tools
setup-vm

# Start swTPM (separate terminal )
vm-swtpm

# Start estserver
vm-estserver

# Start VM
vm-start

# Establish attested TLS connection to Ubuntu VM server
vm-testtool
```

The testtool on the host establishes an attested TLS connection to the testtool running within the
ubuntu VM with server-side authentication and server-side attestation. Find the generated
attestation result in `cmc/data/attestation-result`.

## Further Documentation

### Architecture

An overview of the architecture is given in [Architecture](./doc/architecture.md).

### Detailed Setup

For detailed instructions on how to setup TPM, Intel SGX, Intel TDX or AMD SEV-SNP platforms
including PKI and metadata generation, refer to [Detailed Setup](./doc/setup.md)

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

