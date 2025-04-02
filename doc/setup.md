# Manual Setup

This setup shows step-by-step how to install the tools and generate the metadata for
running the *cmcd*.  It was tested on Ubuntu 24.04 LTS.

For general information on the attestation metadata formats and an explanation of the different
components, see [Architecture](./architecture.md)

## Requirements

- A Linux platform
- For TPM attestation, access to `/dev/tpmrm0` or `/dev/tpm0`.
- For AMD SEV-SNP an SNP-capable AMD server and an SNP VM with access to `/dev/sev-guest`
- for Intel SGX an Intel SGX-capable machine with all required Intel SGX software installed
- for Intel TDX an Intel TDX-capable machine with all required Intel TDX software installed

## Prerequisites

Several packages must be installed for building the `cmc` and generating metadata:
```sh
sudo apt install -y moreutils golang-cfssl build-essential sqlite3 zlib1g-dev libssl-dev jq yq
```
NOTE: For ubuntu, `yq` must be installed as a snap package

Building the *cmcd* requires *go*. Follow https://golang.org/doc/install.

Generating reference values for TDX/TPM-based attestation requires the `tpm-pcr-tools`:
```sh
git clone https://github.com/Fraunhofer-AISEC/tpm-pcr-tools.git
cd tpm-pcr-tools
make
sudo make install
```

## Setup environment

This simply adds `cmc/bin` to the PATH, so that all scripts can be run:
```sh
source env.bash
```

## Setup PKI

Generate a PKI suitable for your needs. A minimal PKI based on `cmc/example-setup/pki-input`
can be created and stored in `cmc/data/pki` as follows:
```sh
mkdir -p cmc/data
setup-pki cmc/example-setup/pki-input cmc/data/pki
```

For a more complex PKI, have a look at the [IDS-Setup](./ids-example-setup.md).

## Platform-specific Setup and Metadata Generation

As the setup differs between the different hardware attestation technologies, the platform-specific
setup is summarized in
- [TPM-Setup](./setup-tpm.md)
- [SNP-Setup](./setup-snp.md)
- [SGX-Setup](./setup-sgx.md)
- [TDX-Setup](./setup-tdx.md)

## Sign the metadata

As soon as the platform-specific metadata has been generated, it must be signed.

This example uses JSON/JWS as serialization format. By default, the metadata is in JSON format
and can be signed like this:

```sh
IN=cmc/data/metadata-raw
OUT=cmc/data/metadata-signed
KEY=cmc/data/pki/signing-cert-key.pem
CHAIN=cmc/data/pki/signing-cert.pem,cmc-data/pki/ca.pem

mkdir -p $OUT

metasign -in $IN/rtm.manifest.json        -out $OUT/rtm.manifest.json        -keys $KEY -x5cs $CHAIN
metasign -in $IN/os.manifest.json         -out $OUT/os.manifest.json         -keys $KEY -x5cs $CHAIN
metasign -in $IN/device.description.json  -out $OUT/device.description.json  -keys $KEY -x5cs $CHAIN
metasign -in $IN/device.config.json       -out $OUT/device.config.json       -keys $KEY -x5cs $CHAIN
```

If the CMC shall work with CBOR metadata, first convert the metadata and then sign as described
above:
```sh
# Convert JSON to CBOR using the converter-tool
cmc/tools/metaconv/metaconv -in <input-file>.json -out <output-file.cbor> -inform json -outform cbor
```

### Build and Run the CMC

Refer to [Build](./build.md) and [Run](./run.md) for building and running the go binaries to
perform remote attestation and establish attested secure channels.