# TPM VM Test-Setup

Describes the setup with a QEMU Ubuntu VM with attached software TPM.

## VM Setup

Creates an ubuntu server VM image with attached swTPM:
```sh
source env.bash
vm-setup
```

## Run CMC

```sh
# Start swTPM (separate terminal)
vm-swtpm

# Start estserver
vm-estserver

# Start VM
vm-start

# Establish attested TLS connection to Ubuntu VM server
vm-testtool
```

The testtool on the host establishes an attested TLS connection to the testtool running within the
ubuntu VM with server-side authentication and server-side attestation.

Find the generated attestation result in `cmc/data/attestation-result`.

## SSH into VM

You can SSH into the VM and copy files to and from the VM:
```sh
vm-ssh [optional-command]

vm-scp vm-ubuntu:/path/to/file/in/vm /path/on/host
```


---


## Experimental: Manually Update Metadata

If another image is to be used, the metadata must be updated. This is an experimental guide
on how this could be achieved.

### Parsing the Reference Values

```sh
vm-swtpm
vm-start
generate-metadata-vm
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