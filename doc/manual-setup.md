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
# 1. Setup a folder for the cmc workspace (e.g. in your home directory)
CMC_ROOT=$HOME/cmc-workspace

# 2. Clone the CMC repo
git clone https://github.com/Fraunhofer-AISEC/cmc $CMC_ROOT/cmc

# 3. Build CMC
cd $CMC_ROOT/cmc
go build ./...

# 4. Install CMC $GOPATH/bin (export PATH=$PATH:$HOME/go/bin -> .profile/.bashrc)
go install ./...
```

## Setup PKI and Metadata

### 1. Create a folder for your CMC configuration

```sh
mkdir -p $CMC_ROOT/cmc-data
```

### 2. Copy and adjust the example metadata templates
For the example, it is sufficient to copy the templates. For information on how to adjust
the metadata, see [Generating Metadata and Setup Alternatives](#generating-metadata-and-setup-alternatives)
```sh
cp -r $CMC_ROOT/cmc/example-setup/* $CMC_ROOT/cmc-data
```

```sh
# 3. Generate a PKI suitable for your needs. You can use the simple PKI example-setup for testing:
$CMC_ROOT/cmc-data/setup-simple-pki -i $CMC_ROOT/cmc-data -o $CMC_ROOT/cmc-data/pki
```

### 3. Generate metadata

The example setup (folder `cmc/example-setup`) contains templates for the required metadata files
in JSON. The attributes of these files can be adjusted according to individual requirements:

- **rtm.manifest.json**: Contains information about the Root of Trust for Measurements, which
usually comprises the reference values (hashes) for BIOS/UEFI, bootloader and other early boot
components
- **os.manifest.json**: Contains the operating system reference values and information
- **app.manifest.json**: Contains the reference values for an app on the system
- **company.description.json**: Optional, metadata describing the operater of the computing platform
- **device.description.json**: Metadata describing the overall platform, contains links to
RTM Manifest, OS Manifest and App Manifests
- **device.config.json**: Signed local device configuration, contains e.g. the parameters for
the Certificate Signing Requests for the attestation and identity keys

### Serialization Format

The attestation report can be serialized to JSON and signed via JSON Web signatures (JWS), or to
CBOR and signed via CBOR Object Signing and Encryption (COSE). This must be specified in the
configuration of the *cmcd* (see [CMCD Configuration](#cmcd-configuration) and the
provisioning server (see [Provisioning Server Configuration](#provisioning-server-configuration))

As CBOR is a binary serialization format, the serialized data is not human-readable. Therefore, the
metadata templates are always in JSON. A converter tool is provided to convert the metadata files
to CBOR before signing them. To convert a metadata file from JSON to CBOR:

```sh
# Convert JSON to CBOR using the converter-tool
$CMC_ROOT/cmc/tools/cmc-converter/cmc-converter -in <input-file>.json -out <output-file.cbor> -inform json -outform cbor
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
```sh
# Parse the values of the RTM PCRs from the kernel's binary bios measurement log
ements as reference values
referenceValues=$(sudo parse-srtm-pcrs -p 0,1,2,3,4,5,6,7 -f json)
# Delete existing reference values in the RTM Manifest
jq 'del(.referenceValues[])' $CMC_ROOT/cmc-data/metadata-raw/rtm.manifest.json | sponge $CMC_ROOT/cmc-data/metadata-raw/rtm.manifest.json
# Add new reference values to the RTM Manifest
jq --argjson ver "$referenceValues" '.referenceValues += $ver' $CMC_ROOT/cmc-data/metadata-raw/rtm.manifest.json | sponge $CMC_ROOT/cmc-data/metadata-raw/rtm.manifest.json

# Parse the values of the OS PCRs from the kernel's binary bios measurement log
referenceValues=$(sudo parse-srtm-pcrs -p 8,9 -f json)
# Delete existing reference values in the OS Manifest
jq 'del(.referenceValues[])' $CMC_ROOT/cmc-data/metadata-raw/os.manifest.json | sponge $CMC_ROOT/cmc-data/metadata-raw/os.manifest.json
# Add new reference values to the OS Manifest
jq --argjson ver "$referenceValues" '.referenceValues += $ver' $CMC_ROOT/cmc-data/metadata-raw/os.manifest.json | sponge $CMC_ROOT/cmc-data/metadata-raw/os.manifest.json
```

**Calculating the reference values based on software artifacts**

This currently only works for QEMU VMs with OVMF and a Linux kernel
```sh
# Calculate reference values for the RTM Manifest
referenceValues=$($(calculate-srtm-pcrs \
      --format json \
      --pcrs 0,1,2,3,6,7 \
      --eventlog \
      --kernel "linux-kernel.bzImage" \
      --ovmf "OVMF.fd" \
      --config "calculate-pcrs.cfg" \
    )

# Delete all existing reference values in the RTM manifest
jq 'del(.referenceValues[])' $CMC_ROOT/cmc-data/metadata-raw/rtm.manifest.json | sponge $CMC_ROOT/cmc-data/metadata-raw/rtm.manifest.json
# Insert new reference values to the RTM Manifest
jq --argjson ver "$referenceValues" '.referenceValues += $ver' $CMC_ROOT/cmc-data/metadata-raw/rtm.manifest.json | sponge $CMC_ROOT/cmc-data/metadata-raw/rtm.manifest.json
```

##### AMD SNP Reference Values

tbd

##### Intel TDX Reference Values

tbd

##### Intel SGX Reference Values

The reference values for Intel SGX consist of a fingerprint of the Intel Root CA certificate, the TCB Info and QE Identity structures, the enclave product ID (ISV Prod ID), the security version of the enclave (ISVSVN), expected enclave attributes (e.g. DEBUG, Mode64Bit, etc.), a hash of the enclave measurement (MRENCLAVE) and a hash of the enclave signing key (MRSIGNER).

The Root CA certificate, TCB Info and QE Identity structures can be retrieved from the [Intel API](https://api.portal.trustedservices.intel.com/content/documentation.html). ISV SVN and ISV Prod ID are assigned by the enclave author. The EGo framework sets these values to 1 by default.
The MRENCLAVE and MRSIGNER values for an enclave can be retrieved via the EGo CLI tool with the commands ```ego uniqueid $ENCLAVE_PROGRAM``` and ```ego signerid $ENCLAVE_PROGRAM```.

### 4. Sign the metadata

This example uses JSON/JWS as serialization format. For different formats
see [Serialization Format](#serialization-format)

```sh
IN=$CMC_ROOT/cmc-data/metadata-raw
OUT=$CMC_ROOT/cmc-data/metadata-signed
KEY=$CMC_ROOT/cmc-data/pki/signing-cert-key.pem
CHAIN=$CMC_ROOT/cmc-data/pki/signing-cert.pem,$CMC_ROOT/cmc-data/pki/ca.pem

mkdir -p $OUT

cmc-signing-tool -in $IN/rtm.manifest.json        -out $OUT/rtm.manifest.json        -keys $KEY -x5cs $CHAIN
cmc-signing-tool -in $IN/os.manifest.json         -out $OUT/os.manifest.json         -keys $KEY -x5cs $CHAIN
cmc-signing-tool -in $IN/device.description.json  -out $OUT/device.description.json  -keys $KEY -x5cs $CHAIN
cmc-signing-tool -in $IN/device.config.json       -out $OUT/device.config.json       -keys $KEY -x5cs $CHAIN
```

### 5. Adjust the configuration files

Adjust the configuration files for the tools as required according to
[Configuration](#cmcd-configuration).

### 6. Run

#### Run the EST and Provisioning Server

```sh
# Start the EST server that supplies the certificates and metadata for the cmcd
./estserver -config $CMC_ROOT/cmc-data/est-server-conf.json
```

#### Run the cmcd

```sh
# Build and run the cmcd
./cmcd -config $CMC_ROOT/cmc-data/cmcd-conf.json
```

#### Generate and Verify Attestation Reports

```sh
# Run the testtool to retrieve an attestation report (stored in current folder unless otherwise specified)
./testtool -mode generate

# Run the testtool to verify the attestation report (stored in current folder unless otherwise specified)
./testtool -mode verify -ca $CMC_ROOT/cmc-data/pki/ca.pem
```

#### Establish Attested TLS Connections

```sh

# Run an attested TLS server
./testtool -mode listen -addr 0.0.0.0:4443 -ca $CMC_ROOT/cmc-data/pki/ca.pem -mtls

# Run an attested TLS client estblishing a mutually attested TLS connection to the server
./testtool -mode dial -addr localhost:4443 -ca $CMC_ROOT/cmc-data/pki/ca.pem -mtls
```

#### Establish Attested HTTPS Connections

```sh
# Run two attested HTTPS servers
./testtool -config $CMC_ROOT/testtool-config.json -addr 0.0.0.0:8081 -mode serve

# Perform multiple user-specified attested HTTPS requests to both servers. Each connection is
# attested, while multiple requests to the same server use the established attested TLS connections
./testtool \
    -config ../../cmc-data/testtool-lib-config.json \
    -addr https://localhost:8081/post,https://localhost:8082/post \
    -mode request \
    -method POST \
    -data "hello from attested HTTPS client" \
    -header "Content-Type: text/plain"
```
