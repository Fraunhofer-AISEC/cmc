# TPM VM Test-Setup

Describes the setup with a QEMU Ubuntu VM with attached software TPM.

As described in [Setup](./setup.md#prerequisites), each command can be prepended with `cmc-docker`
for running in docker, or `cmc-docker` can simply be omitted.

## VM Setup

Creates an ubuntu server VM image with attached swTPM:
```sh
source env.bash
cmc-docker vm-setup
```

## Run CMC

Starts swTPM, EST provisioning server and VM with CMC and [cmcctl](./architecture.md#cmcctl) in
server mode and then establishes server-side attested TLS connection from the host to the VM:
```sh
# Start swTPM (separate terminal)
cmc-docker vm-swtpm

# Start estserver
cmc-docker vm-estserver

# Start VM
cmc-docker vm-start

# Establish attested TLS connection to Ubuntu VM server
cmc-docker vm-cmcctl
```

The [cmcctl](./architecture.md#cmcctl) on the host establishes an attested TLS connection to
the cmcctl running within the ubuntu VM with server-side authentication and server-side
attestation.

Find the generated attestation result in `cmc/data/attestation-result`.

> **Note:** The **attestation might fail**, as this simple demo setup does not aim for a full
> reproducible build of all components. For a successful attestation, you can update the metadata as
> described in [parsing the reference values](#parsing-the-reference-values).

> **Note:** This demo VM is just for demonstration purposes and **not secure**, as secure boot is
> not enabled, the user has root access, and neither file systems nor user space applications are
> measured. [Platform Configuration](./setup-tpm.md#platform-configuration) provides some guidance,
> especially how to activate the IMA to extend the measured boot to the user space.


---


## Troubleshooting

Below you can find some guidance on updating metadata and inspecting the VM.

### Manually Update Metadata

If attestation fails, the metadata must be updated. This is an experimental guide
on how this could be achieved.

#### Parsing the Reference Values

Simply parses the reference values from a running VM:
```sh
cmc-docker vm-swtpm
cmc-docker vm-start
cmc-docker generate-metadata-vm
sign-metadata json
cp data/metadata-signed/* example-setup/vm-config/vm-metadata/
cp data/pki/ca.pem example-setup/vm-config/
```

#### Precomputing the Reference Values

Precomputes the metadata based on software artifacts. Not yet working!
```sh
vm-extract-data
precompute-metadata-vm
cp data/metadata-signed/* example-setup/vm-config/vm-metadata/
cp data/pki/ca.pem example-setup/vm-config/
```

### Access VM

You can access the VM via user `root`, pw `root`.

### SSH into VM

You can SSH into the VM and copy files to and from the VM:
```sh
cmc-docker vm-ssh [optional-command]

cmc-docker vm-scp vm-ubuntu:/path/to/file/in/vm /path/on/host
```

### View Logs

The cmcd and cmcctl server run as systemd [cmcd.service](../example-setup/vm-config/cmcd.service)
and [cmcctl.service](../example-setup/vm-config/cmcctl.service).

Logs can be viewed via:
```sh
journalctl [-f] -u cmcd
journalctl [-f] -u cmcctl
```

### Manually Run Services

The services can also be stopped and manually run:
```sh
systemctl stop cmcd
systemctl stop cmcctl

cmcd -config /etc/cmcd-conf.json
cmcctl -config /etc/cmcctl-conf-vm.json
```