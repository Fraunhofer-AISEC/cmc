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

Refer to [Setup](./doc/setup.md) for instructions on how to setup, configure and run the CMC
on various hardware platforms.

For a quick demo without installing software or requiring actual hardware, use Docker and the
Virtual Machine (VM) with attached swTPM as described in [Setup](./doc/setup.md).

## Documentation

The following contents can be found in the [doc](./doc/) folder:

### Setup

For detailed instructions on how to setup TPM, Intel SGX, Intel TDX or AMD SEV-SNP platforms
including PKI and metadata generation, refer to the [Setup Documentation](./doc/setup.md)

### Build

See [Build Documentation](./doc/build.md) for instructions on how to build the go binaries.

### Run

For configuring and running the go binaries, refer to the
[Run Documentation](./doc/run.md).

### Architecture

An overview of the architecture is given in [Architecture](./doc/architecture.md).

### Metadata

Detailed information on how to generate, sign and parse metadata is given in
[Metadata](./doc/metadata.md).

### Developer Documentation

Refer to [Developer Documentation](./doc/dev.md) for instructions on developing custom applications
using attested TLS or attested HTTPS, as well as for developing the CMC.

### Additional Demo Setups

For an alternative demo setup with a more complex PKI and policies based on the requirements of
the International Data Spaces (IDS), see [IDS Example Setup](./doc/ids-example-setup.md)

