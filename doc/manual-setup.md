# Manual Setup

This setup shows step-by-step how to install the tools, generate the metadata describing the
platform and run and test the tools. It was tested on Ubuntu 22.04 LTS.

## Install Prerequisites

```sh
# Install utils
sudo apt install moreutils golang-cfssl build-essential

# Install tpm-pcr-tools for calculating/parsing TPM PCR values for TPM-based attestation
sudo apt install -y build-essential zlib1g-dev libssl-dev
git clone https://github.com/Fraunhofer-AISEC/tpm-pcr-tools.git
cd tpm-pcr-tools
make
sudo make install # Or launch from individual folders
```

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

This example uses a TPM as hardware trust anchor and an SRTM measured boot. For other setups,
see [Generating Metadata and Setup Alternatives](#generating-metadata-and-setup-alternatives)

```sh
# Parse the values of the RTM PCRs from the kernel's binary bios measurements as reference values
referenceValues=$(sudo parse-srtm-pcrs -p 0,1,2,3,4,5,6,7 -f json)
# Delete existing reference values in the RTM Manifest
jq 'del(.referenceValues[])' $CMC_ROOT/cmc-data/metadata-raw/rtm.manifest.json | sponge $CMC_ROOT/cmc-data/metadata-raw/rtm.manifest.json
jq --argjson ver "$referenceValues" '.referenceValues += $ver' $CMC_ROOT/cmc-data/metadata-raw/rtm.manifest.json | sponge $CMC_ROOT/cmc-data/metadata-raw/rtm.manifest.json

referenceValues=$(sudo parse-srtm-pcrs -p 8,9 -f json)
jq 'del(.referenceValues[])' $CMC_ROOT/cmc-data/metadata-raw/os.manifest.json | sponge $CMC_ROOT/cmc-data/metadata-raw/os.manifest.json
jq --argjson ver "$referenceValues" '.referenceValues += $ver' $CMC_ROOT/cmc-data/metadata-raw/os.manifest.json | sponge $CMC_ROOT/cmc-data/metadata-raw/os.manifest.json
```

### 4. Sign the metadata

This example uses JSON/JWS as serialization format. For different formats
see [Serialization Format](#serialization-format)

```sh
IN=$CMC_ROOT/cmc-data/metadata-raw
OUT=$CMC_ROOT/cmc-data/metadata-signed
KEY=$CMC_ROOT/cmc-data/pki/signing-cert-key.pem
CHAIN=$CMC_ROOT/cmc-data/pki/signing-cert.pem,$CMC_ROOT/cmc-data/pki/ca.pem

mkdir -p $OUT

signing-tool -in $IN/rtm.manifest.json        -out $OUT/rtm.manifest.json        -keys $KEY -x5cs $CHAIN -format json
signing-tool -in $IN/os.manifest.json         -out $OUT/os.manifest.json         -keys $KEY -x5cs $CHAIN -format json
signing-tool -in $IN/device.description.json  -out $OUT/device.description.json  -keys $KEY -x5cs $CHAIN --format json
signing-tool -in $IN/device.config.json       -out $OUT/device.config.json       -keys $KEY -x5cs $CHAIN --format json
```

### 5. Adjust the *cmcd* configuration

Open the cmcd-configuration in `$CMC_ROOT/cmc-data/cmcd-conf.json` and adjust it if required.
For more information about the configuration see [CMCD Configuration](#cmcd-configuration)
or run `cmcd -help`

### 6. Adjust the provisioning server configuration
Open the provisioning server configuration in `$CMC_ROOT/cmc-data/prov-server-conf.json` and
adjust it if required. For more information about the configuration see
[Provisioning Server Configuration](#provisioning-server-configuration) or run `provserver -help`

## Generating Metadata and Setup Alternatives

Metadata and PKI can be generated in different serialization formats and configurations.

### Metadata

The example setup contains templates for the required metadata files in JSON. The attributes
of these files can be adjusted according to individual requirements:

- **rtm.manifest.json**: Contains information about the Root of Trust for Measurements, which
usually comprises the reference values (hashes) for BIOS/UEFI, bootloader and other early boot
components
- **os.manifest.json**: Contains the operating system reference values and information
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
$CMC_ROOT/cmc/tools/converter/converter -in <input-file>.json -out <output-file.cbor> -format json
```

### TPM Setup using Calculated Values

In the example setup, the platform is simply seen as a "good reference platform" and the
reference values are generated through parsing the TPM measurements from the `sysfs`. Ideally, the
reference values are generated from the single software artefacts running on the platform. For
QEMU VMs with OVMF and a kernel with appended initramfs, the `calculate-srtm-pcrs` tool can
be used:

```sh
# 5. a) TPM Setup using calculated values
# Calculate reference values
referenceValues=$(calculate-srtm-pcrs --kernel linux-amd64-virtio-systemd-debug.bzImage --ovmf OVMF-DEBUG.fd --format json --pcrs 0,1,2,3,6,7 --eventlog --config configs/ovmf-f80580f56b.cfg)
# Delete all existing reference values
jq 'del(.referenceValues[])' $CMC_ROOT/cmc-data/metadata-raw/rtm.manifest.json | sponge $CMC_ROOT/cmc-data/metadata-raw/rtm.manifest.json
# Insert new reference values
jq --argjson ver "$referenceValues" '.referenceValues += $ver' $CMC_ROOT/cmc-data/metadata-raw/rtm.manifest.json | sponge $CMC_ROOT/cmc-data/metadata-raw/rtm.manifest.json

referenceValues=$(calculate-srtm-pcrs --kernel linux-amd64-virtio-systemd-debug.bzImage --ovmf OVMF-DEBUG.fd --format json --pcrs 4,5 --eventlog --config configs/ovmf-f80580f56b.cfg)
jq 'del(.referenceValues[])' $CMC_ROOT/cmc-data/metadata-raw/os.manifest.json | sponge $CMC_ROOT/cmc-data/metadata-raw/os.manifest.json
jq --argjson ver "$referenceValues" '.referenceValues += $ver' $CMC_ROOT/cmc-data/metadata-raw/os.manifest.json | sponge $CMC_ROOT/cmc-data/metadata-raw/os.manifest.json
```