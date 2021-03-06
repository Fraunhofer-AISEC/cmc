# CMC

[![build](https://github.com/Fraunhofer-AISEC/cmc/actions/workflows/build.yml/badge.svg)](https://github.com/Fraunhofer-AISEC/cmc/actions/workflows/build.yml)
[![](https://godoc.org/github.com/Fraunhofer-AISEC/cmc?status.svg)](https://pkg.go.dev/github.com/Fraunhofer-AISEC/cmc)
[![Go Report Card](https://goreportcard.com/badge/github.com/Fraunhofer-AISEC/cmc)](https://goreportcard.com/report/github.com/Fraunhofer-AISEC/cmc)

The CMC (originally Connector Measurement Component) repository provides tools and software to
enable remote attestation of computing platforms. It was initially designed as a proposal for
remote attestation within the International Data Spaces (IDS), but can be used for
universal attestation of computing platforms.

## Architecture Overview

![CMC, attestation drivers and exemplary test-connector and client as well as interface descriptions](./doc/overview.svg)

The figure shows how the core components interact with each other. The main software components are:
- The cmcd collects and provides information and attestation reports from the provided trusted hardware
- The test connector and client are exemplary applications that make use of the daemon to create an attested tls connection
- Trusted hardware provides the attestation reports and, if available, key storage and signing functionalities


Refer to the [Architecture](doc/Architecture.md) Readme for more information.

## Prerequistes

- Running the *cmcd* currently requires a Linux platform. If the *cmcd* is configured to use a TPM
for measurements or signing, the *cmcd* must be able to access ```/dev/tpm0```. If AMD SEV-SNP is
used for measurements, the *cmcd* must be run on an AMD server within an SNP Virtual Machine.
- Building the *cmcd* requires *go* (https://golang.org/doc/install)
- Performing a successful remote attestation further requires a correctly configured platform,
configuration data and meta-data about the expected platform state (see
[Manifests and Descriptions](#manifests-and-descriptions))

**Note**: If configured to be used with a TPM, The *cmcd* accesses the TPM and creates keys within
the TPM. You should not run it on your normal work laptop, as it might require the TPM and its key
storage for secure boot, disk encryption or other purposes. Instead, run it on a dedicated
Virtual Machine (VM) or server.

## Quick Start

The CMC repository contains a complete local example setup including a demo CA and all required
configurations and metadata. This setup is for demonstrating purposes only. Furthermore,
it provides testing tools for local and remote attestation.

```sh
# Build and run the provisioning server that supplies the certificates and data for the cmcd
cd cmc/provserver
go build
./provserver --config ../example-setup/prov-server-conf.json

# Build and run the cmcd
cd cmc/cmcd
go build
./cmcd --config ../example-setup/cmcd-conf.json --addr http://127.0.0.1:9001/metadata-signed

# Build the testclient
cd cmc/testclient
go build

# Run the testclient to retrieve an attestation report (stored in cmc/testclient)
./testclient --mode generate

# Run the testclient to verify the attestation report (result also stored in cmc/testclient)
./testclient --mode verify --rootcacertfile ../example-setup/ca/ca.pem

# To test the attested TLS connection
cd cmc/testconnector
go build
./testconnector --rootcacertfile ../example-setup/ca/ca.pem

# Run the testclient to test the attested TLS connection with the connector
./testclient --mode tlsconn -rootcacertfile ../example-setup/ca/ca.pem -connector 127.0.0.1:443 -mTLS
```

**Note**: by default, *cmcd* and *testclient* use localhost port 9955 to communicate. This can be changed in the *cmcd*
configuration and using the ```--addr <host:port>``` command line argument for the testclient.

**Note**: The *cmcd* --addr parameter is the server address where metadata can be found and must
correspond to the address in the *provserver* config

**Note**: The *cmcd* TPM provisioning process includes the verification of the TPM's EK certificate
chain. In the example setup, this verification is turned off, as the database might not contain
the certificate chain for the TPM of the machine the *cmcd* is running on. Instead, simply a
warning is printed. The intermediate and root CA for this chain can be downloaded from the TPM
vendor. The certificates can then be added in to the ```cmc/example-setup/tpm-ek-certs.db```
database. The ```verifyEkCert``` parameter in the *provserver* config can then be set to true.

**Note**: The verification of the attestation report will most likely fail. This is due to the
software on your machine differing from the software defined in the example-setup. Use
the *ids-pcp*-tool to update the manifests and descriptions (see
[Manifests and Descriptions](#manifests-and-descriptions))


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

The repository contains example setups for a TPM based attestation of a device using
Static Root of Trust for Measurements (SRTM) in folder
`ids-pcp/examples/demo-setup/input/srtm-connector` as well a device using Dynamic Root of Trust for
Measurements (DRTM) in folder `ids-pcp/examples/demo-setup/input/drtm-connector`. The values must
be adjusted in the *manifest* files to the values of the platform. For testing, the values can be
retrieved e.g. via the tools ```fwupdtpmevlog``` or ```tpm2_eventlog```.

After the values are adjusted, the manifests and descriptions can be signed by the demo
*ids-pcp* tool and provided to the *cmcd*:

```sh
cd cmc/example-setup
# If desired, generate a new PKI
./generate-pki
# Sign the metadata files
./sign-metadata
```

**Note:** We aim to provide a VM and tools for automatically generating the manifest files
in the suitable format in the future.

## Config Files

The *cmcd* and *provserver* require JSON configuration files. An example setup with all
required configuration files is provided in the ```examples/``` folder of this repository.

The *cmcd* requires a JSON configuration file with the following information:
- **addr**: The address the *cmcd* should listen on, e.g. 127.0.0.1:9955
- **provServerAddr**: The URL of the provisioning server. The server issues certificates for the
TPM or software keys. In case of the TPM, the TPM *Credential Activation* process is performed.
- **localPath**: the local path to store the meta-data and internal files. In a local setup, all
manifests and descriptions must be placed in this folder. If the provisioning server is used for
the meta-data (*cmcd* command line argument *--fetch-metadata*), the *cmcd* will store those files
in this folder. In this case, it is not required that the folder already exists, the *cmcd* will
handle everything automatically
- **fetchMetadata**: Boolean to specify whether the *cmcd* should load/update its metadata from
the provisioning server. If set to false, the *cmcd* expects all files to be present in the
*localPath*
- **measurementInterfaces**: Tells the *cmcd* prover which measurement interfaces to use, currently
supported are "TPM" and "SNP".
- **signingInterface**: Tells the *cmcd* prover with which interface to sign the overall generated
attestation report. Currently supported are "TPM", "SNP", and "SW". **Note**: This is only for the
overall report. The hardware-based measurements are signed by the respective hardware-based keys
of the measurement interface itself. E.g. if the TPM is selected as measurement interface, the
TPM quote will always be signed with the TPM's AK.
- **useIma**: Bool that indicates whether the Integrity Measurement Architecture (IMA) shall be used
- **imaPcr**: TPM PCR where the IMA measurements are recorded (must match the kernel
configuration). The linux kernel default is 10
- **keyConfig**: The algorithm to be used for the *cmcd* keys. Possible values are:  RSA2048,
RSA4096, EC256, EC384, EC521

```json
{
    "addr": "127.0.0.1:9955",
    "provServerAddr": "http://127.0.0.1:9001/",
    "serverPath": "drtm-example/",
    "localPath": "metadata/",
    "fetchMetadata": true,
    "measurementInterfaces": [ "TPM", "SNP" ],
    "signingInterface": "TPM",
    "useIma": false,
    "imaPcr": 10,
    "keyConfig": "EC256"
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
from the *cmcd* config of the individual devices. Inside the folders, the metadata
(manifests and descriptions) for the device must be stored. The files can be generated with
the *ids-pcp* tool.
- **verifyEkCert**: Boolean, specifies if the EK certificate chain should be validated via the
**tpmEkCertDb**
- **tpmEkCertDb**: SQLite database containing intermediate CA and CA certificates from the TPM
manufacturers. The provisioning server uses these certificates to verify the TPM
Endorsement Key (EK) certificate. The repository contains an example database with the
certificates of some TPM manufacturers which can be used. For different manufacturers,
certificates might need to be added.
- **vcekOfflineCaching**: Boolean, specifies whether AMD SEV-SNP VCEK certificates downloaded from the AMD KDS server should be stored locally for later offline retrieval
- **vcekCacheFolder**: The folder the downloaded VCEK certificates should locally be stored (only
relevant if vcekOfflineCaching is set to true)

```json
{
    "port": 9000,
    "deviceSubCaKey": "ca/device_sub_ca-key.pem",
    "deviceSubCaCert": "ca/device_sub_ca.pem",
    "caCert": "ca/ca.pem",
    "httpFolder": "data-server",
    "verifyEkCert": false,
    "tpmEkCertDb": "tpm-ek-certs.db",
    "vcekOfflineCaching": true,
    "vcekCacheFolder": "ca/vceks"
}
```

### Platform Configuration

The *cmcd* does not provide platform security itself, it only allows to make verifiable claims
about the software running on a platform. Thus, a secure base plaftorm is essential for the
overall security of the platform. This includes the kernel configuration, OS configuration,
file systems and software running on the host. Some configurations are mandatory for the *cmcd*
to work (e.g., if used, TPM-support must be enabled in the kernel configuration).

Further information about the platform configuration can be found
[here](doc/platform-configuration.md)

## Build

All binaries can be built with the *go*-compiler. For an explanation of the various flags run
<binary> --help

### Build and Run the Provisioning Server

```sh
cd provserver
go build
./provserver --config <config-file>
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
./cmcd --config <config-file> --addr <server-metadata-address>
# with added custom certificates
SSL_CERT_FILE=../example-setup/pki/ca/ca.pem ./cmcd --config <config-file> --addr <server-metadata-address>
SSL_CERT_DIR=../example-setup/pki/ca/ ./cmcd --config <config-file> --addr <server-metadata-address>
```

### Build and Run the Test Client

```sh
cd testclient
go build
./testclient --mode < generate | verify | tlsconn > [--port <port-number>] [--connector <remote-address>] [--mTLS] [--rootcacertfile <file>] [--policies <file>]
```

### Build and Run the Testconnector

```sh
cd testconnector
go build
./testconnector [--rootcacertfile <file>] [--connector <listen-addr>] [--policies <file>]
```

### Regenerate Protobuf gRPC Interface

```sh
sudo apt install -y protobuf-compiler
cd cmcinterface/
make
```