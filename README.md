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

## Prerequisites

- A Linux platform
- For TPM attestation, access to `/dev/tpm0`.
- For AMD SEV-SNP an SNP-capable AMD server
- Building the *cmcd* requires *go* (https://golang.org/doc/install)

## Quick Start

The CMC repository contains a complete local TPM-based example setup including a demo CA and all
required configurations and metadata. It was tested on Ubuntu 22.04 LTS.

> :warning: **Note:** You should run this only for testing on a development machine, or inside
> a Virtual Machine (VM). The software directly interacts with the TPM

### Setup and Build

Clone the repository:
```sh
git clone https://github.com/Fraunhofer-AISEC/cmc.git
```
Create a demo PKI and all required metadata:
```
./cmc/example-setup/setup-full-simple <cmc-folder> <metadata-folder> json
```
`<cmc-folder>` is the relative or absolute path to the cloned `cmc` repository.
`<metadata-folder>` is an arbitrary folder that will be created and that will store metadata and
configuration files. `json` specifies JSON as the serialization format. `cbor` is possible as well.

For the JSON example configuration folders to work without modifications, choose as `<metadata-folder>`
the folder `cmc-data` located in the same root folder the `cmc` repository resides in.
Export this root folder as `$CMC_ROOT`.

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

The tools can be configured via JSON configuration files and commandline flags. For an explanation,
each binary can be run with the `-help` flag. All configuration options are explained in the
[Configuration Documentation](./doc/configuration.md).

#### Detailed Setup

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

