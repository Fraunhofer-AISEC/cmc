# CMC

## Quick Demo Setup IDS Use Case
The CMC repository also contains a complete local example setup including a demo CA and all required
configurations and metadata matching the specifications for the International Data Spaces (IDS).
The setup script `example-setup/setup-full-ids` clones this
repository to a folder `cmc-workspace` in the home directory and sets up everything to quickly
test remote attestation with the IDS specific roles and CAs. 
It was tested on Ubuntu 22.04 LTS.

> :warning: **Note:** You should run this only for testing on a development machine

```sh
./setup-full-ids
```

**Afterwards, continue with [Run the CMC](#run-the-cmc)**

## Manual Setup

This setup shows step-by-step how to install the tools, generate the metadata describing the
platform and run and test the tools. It was tested on Ubuntu 22.04 LTS.

### Install Prerequisites

```sh
# Install utils
sudo apt install moreutils

# Install cfssl for generating a demo PKI
sudo apt install golang-cfssl

# Install tpm-pcr-tools for calculating/parsing TPM PCR values for TPM-based attestation
sudo apt install -y build-essential zlib1g-dev libssl-dev
git clone https://github.com/Fraunhofer-AISEC/tpm-pcr-tools.git
cd tpm-pcr-tools
make
sudo make install # Or launch from individual folders
```

For the IDS use case, additionally install the [PCP tool](https://github.com/Fraunhofer-AISEC/ids-pcp) 
and its dependencies for preparing a PKI and signed manifests and descriptions as required for this use case.
```sh
# Install sqlite3 for supporting databases for OCSP servers
sudo apt install -y sqlite3
git clone https://github.com/Fraunhofer-AISEC/ids-pcp.git

```

### Build and Install

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

### Setup PKI and Metadata

**1. Create a folder for your CMC configuration**

```sh
mkdir -p $CMC_ROOT/cmc-data
```

**2. Copy and adjust the example metadata templates**
For the example, it is sufficient to copy the templates. For information on how to adjust
the metadata, see [Generating Metadata and Setup Alternatives](#generating-metadata-and-setup-alternatives)
```sh
cp -r $CMC_ROOT/cmc/example-setup/* $CMC_ROOT/cmc-data
```

```sh
# 3. Generate a PKI suitable for your needs. You can use the simple PKI example-setup for testing:
$CMC_ROOT/cmc-data/setup-simple-pki -i $CMC_ROOT/cmc-data -o $CMC_ROOT/cmc-data/pki
```

For the IDS use case, you can set up a simple example for the PKI as follows:
```sh
$CMC_ROOT/cmc-data-ids/setup-pki-ids -p $CMC_ROOT/ids-pcp -o $CMC_ROOT/cmc-data-ids/pki-ids
```

**3. Generate metadata**

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

**4. Sign the metadata**

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
signing-tool -in $IN/ak.certparams.json       -out $OUT/ak.certparams.json       -keys $KEY -x5cs $CHAIN --format json
signing-tool -in $IN/tlskey.certparams.json   -out $OUT/tlskey.certparams.json   -keys $KEY -x5cs $CHAIN --format json
```

**5. Adjust the *cmcd* configuration**

Open the cmcd-configuration in `$CMC_ROOT/cmc-data/cmcd-conf.json` and adjust it if required.
For more information about the configuration see [CMCD Configuration](#cmcd-configuration)
or run `cmcd -help`

**6. Adjust the provisioning server configuration**
Open the provisioning server configuration in `$CMC_ROOT/cmc-data/prov-server-conf.json` and
adjust it if required. For more information about the configuration see
[Provisioning Server Configuration](#provisioning-server-configuration) or run `provserver -help`


## Run the CMC

```sh
# Start the provisioning server that supplies the certificates and metadata for the cmcd
provserver -config $CMC_ROOT/cmc-data/prov-server-conf.json

# Build and run the cmcd
cmcd -config $CMC_ROOT/cmc-data/cmcd-conf.json -addr http://127.0.0.1:9001/metadata-signed

# Run the testclient to retrieve an attestation report (stored in current folder unless otherwise specified)
testclient -mode generate

# Run the testclient to verify the attestation report (stored in current folder unless otherwise specified)
testclient -mode verify -ca $CMC_ROOT/cmc-data/pki/ca.pem [-policies $CMC_ROOT/cmc-data/policies.json]
```

