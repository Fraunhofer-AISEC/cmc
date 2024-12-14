# CMC

[![build](https://github.com/Fraunhofer-AISEC/cmc/actions/workflows/build.yml/badge.svg)](https://github.com/Fraunhofer-AISEC/cmc/actions/workflows/build.yml)
[![](https://godoc.org/github.com/Fraunhofer-AISEC/cmc?status.svg)](https://pkg.go.dev/github.com/Fraunhofer-AISEC/cmc)
[![Go Report Card](https://goreportcard.com/badge/github.com/Fraunhofer-AISEC/cmc)](https://goreportcard.com/report/github.com/Fraunhofer-AISEC/cmc)

The CMC repository provides tools and software to enable remote attestation of computing platforms,
as well as remote attested TLS and HTTPS channels between those platforms. Currently, the CMC
repository supports Trusted Platform Module (TPM) attestation, as well as AMD SEV-SNP attestation.
The goal is to make attestation easy for verifiers without prior knowledge of the software stack,
based on a set of trusted CAs and signed metadata describing the software stack.

*A detailed description of the architecture can be found in our*
*[paper](https://dl.acm.org/doi/pdf/10.1145/3600160.3600171) and in the*
*[documentation](doc/Architecture.md)*

## Requirements

- A Linux platform
- For TPM attestation, access to `/dev/tpmrm0` or `/dev/tpm0`.
- For AMD SEV-SNP an SNP-capable AMD server and an SNP VM with access to `/dev/sev-guest`

## Prerequisites

Several packages must be installed for building the `cmc` and generating metada, which has been
tested for debian and ubuntu:
```sh
sudo apt install -y moreutils golang-cfssl build-essential sqlite3 zlib1g-dev libssl-dev jq yq
```
NOTE: For ubuntu, `yq` must be installed as a snap package

Building the *cmcd* requires *go*. Follow https://golang.org/doc/install.

Generating reference values for TPM-based attestation requires the `tpm-pcr-tools`:
```sh
git clone https://github.com/Fraunhofer-AISEC/tpm-pcr-tools.git "${data}/tpm-pcr-tools"
cd "${data}/tpm-pcr-tools"
make
sudo make install
```

Building the AWS Firmware (OVMF) to calculate the reference values for attestation of AWS AMD SEV-SNP
virtual machines requires [Nix](https://nixos.org/download/)

## Build

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

## Quick Start

Create a demo PKI and all required metadata for a TPM-based attestation:
```
./cmc/example-setup/setup-cmc <cmc-folder> <metadata-folder> json
```
`<cmc-folder>` is the relative or absolute path to the cloned `cmc` repository.
`<metadata-folder>` is an arbitrary folder that will be created and that will store metadata and
configuration files. `json` specifies JSON as the serialization format. `cbor` is possible as well.

For the JSON example configuration folders to work without modifications, choose as `<metadata-folder>`
the folder `cmc-data` located in the same root folder the `cmc` repository resides in.
Export this root folder as `$CMC_ROOT`.

The CMC repository contains a complete local TPM-based example setup including a demo CA and all
required configurations and metadata. It was tested on Ubuntu 22.04 LTS.

> :warning: **Note:** You should run this only for testing on a development machine, or inside
> a Virtual Machine (VM). The software directly interacts with the hardware (TPM, SNP).

### Run

The tools can generate and verify attestation reports, establish attested TLS connections and
establish attested HTTPS connections. For detailed instructions refer to
[Manual Setup](./doc/manual-setup.md)

```sh
# Start the EST server that supplies the certificates and metadata for the cmcd
./estserver -config $CMC_ROOT/cmc-data/est-server-conf.json

# Build and run the cmcd
./cmcd -config $CMC_ROOT/cmc-data/cmcd-conf.json

# Run an attested TLS server
./testtool -config $CMC_ROOT/cmc-data/testtool-conf.json -mode listen

# Run an attested TLS client estblishing a mutually attested TLS connection to the server
./testtool -config $CMC_ROOT/cmc-data/testtool-conf.json -mode dial
```

**Note**: The *cmcd* TPM provisioning process includes the verification of the TPM's EK certificate
chain. In the example setup, this verification is turned off, as the database might not contain
the certificate chain for the TPM of the machine the *cmcd* is running on. Instead, simply a
warning is printed. The intermediate and root CA for this chain can be downloaded from the TPM
vendor. The certificates can then be added in to the `cmc/example-setup/tpm-ek-certs.db`
database. The `verifyEkCert` parameter in the *estserver* config can then be set to true.

## Further Documentation

### Architecture

An overview of the architecture is given in [Architecture](./doc/Architecture.md).

### Configuration

The tools can be configured via JSON configuration files and commandline flags. The configuration
is further explained in [Configuration Documentation](./doc/configuration.md).

### Detailed Setup

For instructions on creating and signing the metadata with an arbitrary PKI yourself,
see [Manual Setup](./doc/manual-setup.md)

### Build

See [Build Documentation](./doc/build.md)

### Integration

Usually, the attested TLS or HTTPS libraries are used within own projects to provide attestation
for TLS or HTTPS connections, as described in [Integration](./doc/integration.md)

### Additional Demo Setups

For an alternative demo setup with a more complex PKI and policies based on the requirements of
the International Data Spaces (IDS), see [IDS Example Setup](./doc/ids-example-setup.md)

