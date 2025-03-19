# Manual Setup

This setup shows step-by-step how to install the tools, generate the metadata describing the
platform and run and test the tools. It was tested on Ubuntu 22.04 LTS.

## Install Prerequisites

Install utilities for building and setting up the PKI:
```sh
sudo apt install moreutils golang-cfssl build-essential
```

### TPM-specific Setup
Install tpm-pcr-tools for calculating/parsing TPM PCR values for TPM-based attestation:
```sh
sudo apt install -y build-essential zlib1g-dev libssl-dev
git clone https://github.com/Fraunhofer-AISEC/tpm-pcr-tools.git
cd tpm-pcr-tools
make
sudo make install # Or launch from individual folders
```

### Intel SGX-specific Setup

Install the Intel SGX DCAP libraries and utilities according to the Intel
[manual](https://www.intel.com/content/www/us/en/developer/articles/guide/intel-software-guard-extensions-data-center-attestation-primitives-quick-install-guide.html).

Install the [EGo framework](https://github.com/edgelesssys/ego).


## Build and Install the CMC and Tools

```sh
# Clone the CMC repo
git clone https://github.com/Fraunhofer-AISEC/cmc

# Build CMC
cd cmc
go build ./...

# Install CMC $GOPATH/bin (export PATH=$PATH:$HOME/go/bin -> .profile/.bashrc)
go install ./...
```

## Setup PKI and Metadata

### 1. Create a folder for your CMC configuration

Do this outside the repository:
```sh
mkdir -p cmc-data
```

### 2. Copy and adjust the example metadata templates
For the example, it is sufficient to copy the templates. For information on how to adjust
the metadata, see [Generating Metadata and Setup Alternatives](#generating-metadata-and-setup-alternatives)
```sh
cp -r cmc/example-setup/* cmc-data
```

Generate a PKI suitable for your needs. A minimal PKI can be setup as follows:
```sh
# Generate example PKI
./cmc-data/setup-pki -i ./cmc-data -o ./cmc-data/pki
```

For a more complex PKI, have a look at the [IDS-Setup](./ids-example-setup.md).

### 3. Generate metadata

The example setup (folder `cmc/example-setup`) contains templates for the required metadata files
in JSON.

- **device.description.json**: Metadata describing the overall platform
- **manifest.description.json**: Embedded into device description, describes an instance of a manifest (i.e., a software layer or application)
- **manifest.json**: Template for a manifest containing reference values for a specific software layer or single application
- **company.description.json**: Optional, metadata describing the operater of the computing platform
- **device.config.json**: Signed local device configuration, contains e.g. the parameters for
the Certificate Signing Requests for the attestation and identity keys

### Serialization Format

The attestation report can be serialized to JSON and signed via JSON Web signatures (JWS), or to
CBOR and signed via CBOR Object Signing and Encryption (COSE). This must be specified in the
configuration of the *cmcd* (see [CMCD Configuration](#cmcd-configuration)) and the
provisioning server (see [Provisioning Server Configuration](#provisioning-server-configuration))

As CBOR is a binary serialization format, the serialized data is not human-readable. Therefore, the
metadata templates are always in JSON. A converter tool is provided to convert the metadata files
to CBOR before signing them. To convert a metadata file from JSON to CBOR:

```sh
# Convert JSON to CBOR using the converter-tool
cmc/tools/metaconv/metaconv -in <input-file>.json -out <output-file.cbor> -inform json -outform cbor
```

#### Reference Values

The self-contained attestation reports (see [Architecture](./Architecture.md)) contain signed
reference-values that describe the legitimate software that is expected to be running on the
platform. The trust in the measurements comes from hardware-based measurement technologies, such
as TPMs or Confidential Computing technologies. The reference values for the proving platform must
be generated based on the used technology.

##### TPM Reference Values

The reference values can either be parsed once on a good reference platform in a secure environment,
or they can be calculated based on the built software artifacts of a computing platform (e.g.,
within a build-system such as *Yocto* or *Buildroot*). Tools for parsing and calculated
are available as open source [tpm-pcr-tools]().

**Parsing the reference values on a good reference platform and inserting them into the manifest**

Parse the values of the RTM PCRs from the kernel's binary bios measurement log
```sh
sudo parse-srtm-pcrs -p 0,1,2,3,4,5,6,7 -f json
```
Then insert those values into the json `referenceValues` array in the RTM manifest.

Parse the values of the OS PCRs from the kernel's binary bios measurement log:
```sh
sudo parse-srtm-pcrs -p 8,9,11,12,14,15 -f json
```
Then insert those values into the json `referenceValues` array in the OS manifest.

For the host applications, if the kernel's Integrity Measurement Architecture (IMA) is activated:
```sh
sudo parse-ima-pcr
```
Then insert those values into the json `referenceValues` array in an app manifest.

For OCI containers, currently the `containerd` tool `ctr` is supported with the custom cmc
runtime `cmc/tools/containerd-shim-cmc-v1/containerd-shim-cmc-v1`:
```sh
sudo ctr run --runtime ${runtime} -t --rm docker.io/library/ubuntu:22.04 CMC_GENERATE_APP_MANIFEST
```
the reference values are generated at `/tmp/container-refs` and must be put into an app manifest.

**Calculating the reference values based on software artifacts**

This currently only works for QEMU VMs with OVMF and a Linux kernel. it is recommended to use
the parsing alternative.

Calculate the RTM Manifest reference values:
```sh
calculate-srtm-pcrs \
      --format json \
      --pcrs 0,1,2,3,6,7 \
      --eventlog \
      --kernel "linux-kernel.bzImage" \
      --ovmf "OVMF.fd" \
      --config "calculate-pcrs.cfg" \
```
Then insert those values into the json `referenceValues` array in the RTM Manifest.

Calculate the OS Manifest reference values:
```sh
calculate-srtm-pcrs \
    --kernel "linux-kernel.bzImage" \
    --cmdline "linux-commandline" \
    --ovmf "OVMF.fd" \
    --format json \
    --pcrs "4,5,8,9,11,12,13,14,15" \
    --eventlog \
```
Then insert those values into the json `referenceValues` array in the OS Manifest.

For the host applications, if the kernel's Integrity Measurement Architecture (IMA) is activated:
```sh
# In this case, use PCR10 and the IMA ima-ng template for all folders containing binaries and libs
sudo calculate-ima-pcr -t 10 -i ima-ng -p /usr/bin -p /usr/sbin -p /usr/lib
```
Then insert those values into an app manifest.

For OCI containers, the `buildah` and `umoci` tool can be used in combination with the custom
`cmc/tools/measure-bundle/measure-bundle` tool can be used:

```sh
buildah pull ubuntu:22.04
buildah push ubuntu:22.04 oci-archive:myimage-oci.tar:latest

tar -xvf myimage-oci.tar
(cd image ; umoci unpack --rootless --image ./:latest bundle)

measure-bundle -config image/bundle/config.json" -rootfs image/bundle/rootfs)
```
Then, insert those reference values into an App Manifest.

##### AMD SNP Reference Values

tbd

##### Intel TDX Reference Values

tbd

##### Intel SGX Reference Values

The reference values for Intel SGX consist of a fingerprint of the Intel Root CA certificate, the TCB Info and QE Identity structures, the enclave product ID (ISV Prod ID), the security version of the enclave (ISVSVN), expected enclave attributes (e.g. DEBUG, Mode64Bit, etc.), a hash of the enclave measurement (MRENCLAVE) and a hash of the enclave signing key (MRSIGNER).

The Root CA certificate, TCB Info and QE Identity structures can be retrieved from the [Intel API](https://api.portal.trustedservices.intel.com/content/documentation.html). ISV SVN and ISV Prod ID are assigned by the enclave author. The EGo framework sets these values to 1 by default.
The MRENCLAVE and MRSIGNER values for an enclave can be retrieved via the EGo CLI tool with the commands `ego uniqueid $ENCLAVE_PROGRAM` and `ego signerid $ENCLAVE_PROGRAM`.

### 4. Sign the metadata

This example uses JSON/JWS as serialization format. For different formats
see [Serialization Format](#serialization-format)

```sh
IN=cmc-data/metadata-raw
OUT=cmc-data/metadata-signed
KEY=cmc-data/pki/signing-cert-key.pem
CHAIN=cmc-data/pki/signing-cert.pem,cmc-data/pki/ca.pem

mkdir -p $OUT

metasign -in $IN/rtm.manifest.json        -out $OUT/rtm.manifest.json        -keys $KEY -x5cs $CHAIN
metasign -in $IN/os.manifest.json         -out $OUT/os.manifest.json         -keys $KEY -x5cs $CHAIN
metasign -in $IN/device.description.json  -out $OUT/device.description.json  -keys $KEY -x5cs $CHAIN
metasign -in $IN/device.config.json       -out $OUT/device.config.json       -keys $KEY -x5cs $CHAIN
```

### 5. Adjust the configuration files

Adjust the configuration files for the tools as required according to
[Configuration](#cmcd-configuration).

### 6. Run

#### Run the EST and Provisioning Server

```sh
# Start the EST server that supplies the certificates and metadata for the cmcd
./estserver -config cmc-data/est-server-conf.json
```

#### Run the cmcd

```sh
# Build and run the cmcd
./cmcd -config cmc-data/cmcd-conf.json
```

#### Generate and Verify Attestation Reports

```sh
# Run the testtool to retrieve an attestation report (stored in current folder unless otherwise specified)
./testtool -mode generate

# Run the testtool to verify the attestation report (stored in current folder unless otherwise specified)
./testtool -mode verify -ca cmc-data/pki/ca.pem
```

#### Establish Attested TLS Connections

```sh

# Run an attested TLS server
./testtool -mode listen -addr 0.0.0.0:4443 -ca cmc-data/pki/ca.pem -mtls

# Run an attested TLS client estblishing a mutually attested TLS connection to the server
./testtool -mode dial -addr localhost:4443 -ca cmc-data/pki/ca.pem -mtls
```

#### Establish Attested HTTPS Connections

```sh
# Run two attested HTTPS servers
./testtool -config testtool-config.json -addr 0.0.0.0:8081 -mode serve

# Perform multiple user-specified attested HTTPS requests to both servers. Each connection is
# attested, while multiple requests to the same server use the established attested TLS connections
./testtool \
    -config ../../cmc-data/testtool-config.json \
    -addr https://localhost:8081/post,https://localhost:8082/post \
    -mode request \
    -method POST \
    -data "hello from attested HTTPS client" \
    -header "Content-Type: text/plain"
```
