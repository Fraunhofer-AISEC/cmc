# TPM VM Test-Setup

Describes the setup with a QEMU Ubuntu VM with attached software TPM.

As described in [Setup](./setup.md#prerequisites), each command can be prepended with `cmc-docker`
for running in docker, or `cmc-docker` can simply be omitted. However, as e.g. old QEMU versions
lead to different reference values, the attestation on systems other than ubuntu 24.04 might fail if
docker is not used.

## VM Setup

Creates an ubuntu server VM image with attached swTPM:
```sh
source env.bash
cmc-docker vm-setup
```

## Run CMC

```sh
# Start swTPM (separate terminal)
cmc-docker vm-swtpm

# Start estserver
cmc-docker vm-estserver

# Start VM
cmc-docker vm-start

# Establish attested TLS connection to Ubuntu VM server
cmc-docker vm-testtool
```

The testtool on the host establishes an attested TLS connection to the testtool running within the
ubuntu VM with server-side authentication and server-side attestation.

Find the generated attestation result in `cmc/data/attestation-result`.

## SSH into VM

You can SSH into the VM and copy files to and from the VM:
```sh
cmc-docker vm-ssh [optional-command]

cmc-docker vm-scp vm-ubuntu:/path/to/file/in/vm /path/on/host
```


---


## Experimental: Manually Update Metadata

If another image is to be used, the metadata must be updated. This is an experimental guide
on how this could be achieved.

### Parsing the Reference Values

```sh
cmc-docker vm-swtpm
cmc-docker vm-start
cmc-docker generate-metadata-vm
sign-metadata json
cp data/metadata-signed/* example-setup/vm-config/vm-metadata/
cp data/pki/ca.pem example-setup/vm-config/
```

### Precomputing the Reference Values

```sh
vm-extract-data
precompute-metadata-vm
cp data/metadata-signed/* example-setup/vm-config/vm-metadata/
cp data/pki/ca.pem example-setup/vm-config/
```