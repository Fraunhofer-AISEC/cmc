# Connector Measurement Component

[![build](https://github.com/Fraunhofer-AISEC/cmc/actions/workflows/build.yml/badge.svg)](https://github.com/Fraunhofer-AISEC/cmc/actions/workflows/build.yml)
[![](https://godoc.org/github.com/Fraunhofer-AISEC/cmc?status.svg)](https://pkg.go.dev/github.com/Fraunhofer-AISEC/cmc)
[![Go Report Card](https://goreportcard.com/badge/github.com/Fraunhofer-AISEC/cmc)](https://goreportcard.com/report/github.com/Fraunhofer-AISEC/cmc)

The Connector Measurement Component (CMC) repository provides tools and software to
enable remote attestation of computing platforms in the International Data Spaces (IDS).

## Prerequistes

- Running the *cmcd* currently requires a Linux platform with access to ```/dev/tpm0```.
- Building the *cmcd* requires *go* (https://golang.org/doc/install)
- Performing a successful remote attestation further requires a correctly configured platform,
configuration data and meta-data about the expected platform state (see
[Manifests and Descriptions](#manifests-and-descriptions))

**Note**: The *cmcd* accesses the TPM and creates keys within the TPM. It is intended to run on
a Virtual Machine or a machine/server intended to be used as a connector. You should not run it
on your normal work laptop, as it might require the TPM and its key storage for secure boot,
disk encryption or other purposes.

## Quick Start

The CMC repository contains a complete local example setup including a demo CA and all required
configurations and metadata. This setup is for demonstrating purposes only. Furthermore,
it contains a *testclient* that can be run on the same machine to test the generation and
verification of an attestation report without requiring a second machine and remote attestation
capable network protocol.

```sh
# Build and run the provisioning server that supplies the certificates and data for the cmcd
cd cmc/provserver
make
./provserver --config ../example-setup/prov-server-conf.json

# Build and run the cmcd
cd cmc/cmcd
make
# Note: on subsequent runs, --fetch-metadata is not required until the configuration changes
./cmcd --config ../example-setup/cmcd-conf.json --fetch-metadata

# Build the testclient
cd cmc/testclient
make

# Run the testclient to retrieve an attestation report (stored in cmc/testclient)
./testclient --mode generate

# Run the testclient to verify the attestation report (result also stored in cmc/testclient)
./testclient --mode verify
```

**Note**: *cmcd* and *testclient* use port 9955 as default. This can be changed for both modules
using the ```--port <port-number>``` command line argument.

**Note**: The *cmcd* TPM provisioning process includes the verification of the TPM's EK certificate
chain. In the example setup, this verification is turned off, as the database might not contain
the certificate chain for the TPM of the machine the *cmcd* is running on. Instead, simply a
warning is printed. The intermediate and root CA for this chain can be downloaded from the TPM
vendor. The certificates can then be added in to the ```cmc/example-setup/tpm-ek-certs.db```
database. The ```verifyEkCert``` parameter in the *provserver* config can then be set to true.

**Note**: The verification of the attestation report will most likely fail. This is, because the
software on your machine is different compared to the software defined in the example-setup. Use
the *ids-pcp*-tool to update the manifests and descriptions (see
[Manifests and Descriptions](#manifests-and-descriptions))

## Repository Description

The CMC daemon (*cmcd*) is the main component running on the platform. On request, the cmcd either
generates or verifies an attestation-report, i.e. the state of the platform. The cmcd provides
a gRPC interface to access its services (*cmcinterface*). For the generation and verification
of attestation reports, the *cmcd* relies on the *attestationreport* module.

The *attestationreport* module provides a generic JSON-based serialization format to summarize
the meta-data describing the software running on the computer platform. Enabling trust in this
meta-data requires a hardware-based Root-of-Trust (RoT) that provides the possibility to store keys
and measurements of the software running on the platform. The *attestationreport* therefore
implements a generic *Measurement* interface, as well as the generic go *crypto.PrivateKey* and
*crypto.PublicKey* interfaces. These interfaces must be implemented by *drivers* that provide
access to a hardware based RoT.

Currently, this repository contains the *tpmdriver* module to interface with a Trusted Platform
Module (TPM) as the RoT. The TPM is used to store cryptographic keys, store the software
measurements (hashes) in its Platform Configuration Registers (PCRs) during the *Measured Boot*
and to generate and sign *Quotes* which can be used to verify the platform state. Furthermore, the
*tpmdriver* can use the *ima* module interfacing with the kernel's Integrity Measurement
Architecture (IMA) for obtaining detailed measurement lists of the kernel modules, firmware and
optionally further components running on the platform.

During TPM provisioning, the cmcd requires interaction with a provisioning server (*provserver*)
to acquire certificates for its TPM-based keys. Optionally, the provisioning server can
also provide the metadata (manifests and configurations) for the *cmcd* (*cmcd* command line
argument *--fetch-metadata*, see below). This is just for demonstration. In production, the
functionality usually will be splitted in an IDS and operator server.

## Manifests and Descriptions

The *cmcd* requires metadata (manifests and descriptions) that describe the platform and the
software artefacts running on the platform. A successful remote attestation requires signed
manifests for all components running on the platform. In a productive setup, it would be the
task of a developer of an IDS component to deliver a manifest together with the software component.

For demonstration purposes, this meta-data can be generated via the *ids-pcp* tool, which is also
open source:

```sh
git clone https://github.com/Fraunhofer-AISEC/ids-pcp
```

The repository contains example setups for a TPM based attestation of an SRTM connector
(```ids-pcp/examples/demo-setup/input/srtm-connector```) as well as a DRTM connector
(```ids-pcp/examples/demo-setup/input/drtm-connector```). The values must be adjusted in the
*manifest* files to the values of the platform. For testing, the values can be retrieved e.g.
via the tools ```fwupdtpmevlog``` or ```tpm2_eventlog```.

After the values are adjusted, the manifests and descriptions can be signed by the demo
*ids-pcp* tool and provided to the *cmcd*:

```sh
cd ids-pcp/examples
./example_pcp_demo_setup
# <serverPath> must be set to the "serverPath" config of the cmcd (see Config Files)
cp -r demo_setup/pki/ca <cmc-path>/example-setup/data-server/<serverPath>
cp demo_setup/signed/<drtm/srtm connector>/* <cmc-path>/example-setup/data-server/<serverPath>
```

**Note:** We aim to provide a VM and tools for automatically generating the manifest files
in the suitable format in the future.

## Config Files

The *cmcd* and *provserver* require JSON configuration files. An example setup with all
required configuration files is provided in the ```examples/``` folder of this repository.

The *cmcd* requires a JSON configuration file with the following information:
- **provServerAddr**: The URL of the provisioning server (e.g. http://127.0.0.1.9000/). The server
serves two purposes: 1) It verifies that the TPM keys were generated on a genuine TPM via EK
certificates 2) it optionally provides the meta-data (manifests and descriptions) for the connector
(*cmcd* command line argument *--fetch-metadata*)
- **serverPath**: The HTTP server path for the individual connector (e.g. **data-connector0** if
the full path is "http://127.0.0.1:9000/data-connector0"). This configuration is optional and only
required if the meta-data files shall be retrieved via the config server (*cmcd* command line
argument *--fetch-metadata*)
- **localPath**: the local path to store the meta-data and internal files. In a local setup, all
manifests and descriptions must be placed in this folder. If the provisioning server is used for
the meta-data (*cmcd* command line argument *--fetch-metadata*), the *cmcd* will store those files
in this folder. In this case, it is not required that the folder already exists, the *cmcd* will
handle everything automatically
- **useIma**: Bool that indicates whether the Integrity Measurement Architecture (IMA) shall be used
- **imaPcr**: TPM PCR where the IMA measurements are recorded (must match the kernel
configuration). The linux kernel default is 10

```json
{
"configServerAddr": "http://127.0.0.1:9000/",
"serverPath": "data-connector0/",
"localPath": "connector-data/",
"useIma": true,
"imaPcr": 10
}
```

The provisioning server requires a configuration file with the following information:
- **port**: The port the server should listen on
- **deviceSubCaKey**: The private key of the CA used to sign the device certificates. For the demo,
the *Device Sub CA* key from the *ids-pcp* tool located in
```ids-pcp/examples/demo_setup/pki/ca/device_sub_ca-key.pem``` can be used
- **deviceSubCaCert**: The certificate of the CA used to sign the device certificates. For the
demo, the *Device Sub CA* certificate from the *ids-pcp* tool located in
```ids-pcp/examples/demo_setup/pki/ca/device_sub_ca.pem``` can be used
- **caCert**: The root CA. For the demo, the *CA* certification from the *ids-pcp* tool
located in ```ids-pcp/examples/demo_setup/pki/ca/ca.pem``` can be used
- **httpFolder**: The root folder containing metadata (manifests and descriptions) that is served
by the provisioning server. This root folder must contain folders that match the **serverPath**
from the *cmcd* config of the individual connectors. Inside the folders, the metadata
(manifests and descriptions) for the connector must be stored. The files can be generated with
the *ids-pcp* tool.
- **verifyEkCert**: Boolean, specifies if the EK certificate chain should be validated via the
**tpmEkCertDb**
- **tpmEkCertDb**: SQLite database containing intermediate CA and CA certificates from the TPM
manufacturers. The provisioning server uses these certificates to verify the TPM
Endorsement Key (EK) certificate. The repository contains an example database with the
certificates of some TPM manufacturers which can be used. For different manufacturers,
certificates might need to be added.

```json
{
    "port": 9000,
    "deviceSubCaKey": "ca/device_sub_ca-key.pem",
    "deviceSubCaCert": "ca/device_sub_ca.pem",
    "caCert": "ca/ca.pem",
    "httpFolder": "data-server",
    "verifyEkCert": false,
    "tpmEkCertDb": "tpm-ek-certs.db"
}
```

### Platform Configuration

The *cmcd* does not provide platform security itself, it only allows to make verifiable claims
about the software running on a platform. Thus, a secure base plaftorm is essential for the
overall security of the platform. This includes the kernel configuration, OS configuration,
file systems and software running on the host. Some configurations are mandatory for the *cmcd*
to work (e.g. TPM-support must be enabled in the kernel configuration).

Further information about the platform configuration can be found
[here](doc/platform-configuration.md)

## Build

All binaries can be built with the *go*-compiler:

### Build and Run the Provisioning Server

```sh
cd provserver
make
sudo ./provserver --config <config-file>
```

### Build and Run the CMC Daemon

```sh
cd cmcd
make
sudo ./cmcd --config <config-file> [--fetch-metadata] [--port <port-number>]

```

### Build and Run the Test Client

```sh
# Terminal 1:
sudo ./cmcd --config <config-file> [--port <port-number>]

# Terminal 2:
cd testclient
make
./testclient --mode [ generate | verify ] [--port <port-number>]
```

### Regenerate Protobuf gRPC Interface

```sh
sudo apt install -y protobuf-compiler
cd cmcinterface/
make
```
