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

> :warning: **Note:** You should run the CMC only for testing on a development machine, or inside
> a Virtual Machine (VM) or container. The software directly interacts with the hardware (TPM, SNP,
> SGX, or TDX).

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

### Generate metadata

```sh
source env.bash
setup-cmc <driver>
```
This will create and store an example PKI, metadata and configuration files in `cmc/data`.
`driver` can be `tpm` for TPM, `sgx` for Intel SGX, `tdx` for Intel TDX, or `snp` for AMD SEV-SNP.

Modify the paths in `cmc/example-setup/configs`. Either use absolute paths or paths relative
to your working directory.

### Run

The tools can generate and verify attestation reports, establish attested TLS connections and
establish attested HTTPS connections. For detailed instructions refer to the
[Detailed Setup](./doc/setup.md)

```sh
# Start the EST server that supplies the certificates and metadata for the cmcd
./estserver -config cmc/example-setup/configs/est-server-conf.json

# Build and run the cmcd (Adjust driver to tpm, sgx, tdx, or snp)
./cmcd -config cmc/example-setup/configs/cmcd-conf.json

# Run an attested TLS server
./testtool -config cmc/example-setup/configs/testtool-conf.json -mode listen

# Run an attested TLS client estblishing a mutually attested TLS connection to the server
./testtool -config cmc/example-setup/configs/testtool-conf.json -mode dial
```

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

