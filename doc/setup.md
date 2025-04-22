# Manual Setup

This setup shows step-by-step how to install the tools and generate the metadata for
running the *cmcd*.  It was tested on Ubuntu 24.04 LTS.

For general information on the attestation metadata formats and an explanation of the different
components, see [Architecture](./architecture.md)

## Setup environment

This simply adds `cmc/bin` to the PATH, so that the scripts can be run:
```sh
source env.bash
```

## Requirements

- A Linux platform
- For TPM attestation, access to `/dev/tpmrm0` or `/dev/tpm0`.
- For AMD SEV-SNP an SNP-capable AMD server and an SNP VM with access to `/dev/sev-guest`
- for Intel SGX an Intel SGX-capable machine with all required Intel SGX software installed
- for Intel TDX an Intel TDX-capable machine with all required Intel TDX software installed

## Prerequisites

The required prerequisites vary depending on whether Docker is used.

### Docker

We provide a [Docker Image](../example-setup/docker/cmc.dockerfile), so that it is not required to
install any prerequisites. The only requirement in this case is that docker is installed.

The docker container bind-mounts the repository root as the current user, i.e all artifacts are
built within the same location as without docker, and in many cases, commands can even be used
interchangeably with and without docker. For running any command within the docker container, simply
prepend `cmc-docker` to the command, e.g., `cmc-docker vm-setup` instead of `vm-setup`.

### Non-Docker

If docker is not used, the following prerequisites must be installed:

Building the *cmcd* requires *go*. Follow https://golang.org/doc/install.

Furthermore, several packages must be installed for building the *cmc* and generating metadata:
```sh
sudo apt install -y build-essential libssl-dev golang-cfssl jq yq
```
> NOTE: For ubuntu, `yq` must be installed as a snap package

Building other components, such as the OVMF and swTPM for the demo virtual machine, requires further packages:
```sh
sudo apt install -y moreutils sqlite3 zlib1g-dev libssl-dev protoc-gen-go protoc-gen-go-grpc \
                    nasm acpica-tools uuid-dev libtasn1-dev libjson-glib-1.0-0 libjson-glib-dev \
                    libgnutls28-dev socat zlib1g-dev libseccomp-dev moreutils python-is-python3 \
                    libtool expect
```

Generating reference values for TDX/TPM-based attestation requires the `tpm-pcr-tools`:
```sh
git clone https://github.com/Fraunhofer-AISEC/tpm-pcr-tools.git
cd tpm-pcr-tools
make
sudo make install
```

## Platform-specific Setup and Metadata Generation

As the setup differs between the different hardware attestation technologies, the platform-specific
setup is summarized in
- [VM-Setup](./setup-vm.md)
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
