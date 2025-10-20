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

# Start estserver (separate terminal)
cmc-docker vm-estserver

# Start VM (separate terminal)
cmc-docker vm-start

# Establish attested TLS connection to Ubuntu VM server (separate terminal)
cmc-docker vm-cmcctl

# Attestation will likely fail because of outdated artifacts. Update
cmc-docker vm-update-metadata

# Run again
cmc-docker vm-cmcctl
```

The [cmcctl](./architecture.md#cmcctl) on the host establishes an attested TLS connection to
the cmcctl running within the ubuntu VM with server-side authentication and server-side
attestation.

Find the generated attestation result in `cmc/data/attestation-result.json`.

> **Note:** This demo VM is just for demonstration purposes and **not secure**, as secure boot is
> not enabled, the user has root access, and neither file systems nor user space applications are
> measured. [Platform Configuration](./setup-tpm.md#platform-configuration) provides some guidance,
> especially how to activate the IMA to extend the measured boot to the user space.

## Connecting to the CMC

The VM exposes the CMC via QEMU port forwarding. You can connect to the CMC from the host, as well
as from within the VM. The CMC exposes the [cmcd socket api](./cmcd-api.md) on port `9955` and the
[attested https api](./attestation-protocol.md) on port `4443`.

To connect to the CMC API, simply send a `TCP` request with a payload as documented in
[cmcd socket api](./cmcd-api.md) to `127.0.0.1:9955`. To perform an attestedHTTPS request,
send a request according to [attested https api](./attestation-protocol.md) to
`https://127.0.0.1:4443`.

You can test, that the connection works through either running `cmc-docker vm-cmcctl` or
`openssl s_client -connect 127.0.0.1:4443`. When using the latter, you will get errors because of
unknown certificates, but you will be able to see the certificates and the first post-handshake
attestation protocol response (e.g., `{"version":"1.0.0","attest":2}`).

---


## Diagnostics and Troubleshooting

Below you can find some guidance on updating metadata and inspecting the VM.

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

### Manually Update Metadata

If attestation fails, the metadata must be updated. This is an experimental guide
on how this can be achieved.

#### Parsing the Reference Values

Simply parses the reference values from a running VM:
```sh
cmc-docker vm-swtpm
cmc-docker vm-start
cmc-docker update-metadata-vm
```

#### Precomputing the Reference Values

Precomputes the metadata based on software artifacts. Not yet working!
```sh
vm-extract-data
precompute-metadata-vm
cp data/metadata-signed/* example-setup/vm-config/vm-metadata/
cp data/pki/ca.pem example-setup/vm-config/metadata-ca.pem
```

### Manually Run Services

The services can also be stopped and manually run:
```sh
systemctl stop cmcd
systemctl stop cmcctl

cmcd -config /etc/cmcd-conf.json
cmcctl -config /etc/cmcctl-conf-vm.json
```

### Update VM Configuration

cloud-init does only run on the first boot. If any cloud-init provisioned data is changed, the
simplest approach is to delete `cmc/vm/images/noble-server-cloudimg-amd64.img` and re-run
`cmc-docker vm-setup`.

## Further Documentation

Building and installing the individual components with various flags is described in the
[Build](./build-and-install.md) documentation. A more detailed description on how to configure and
run the components is described in the [Run](./run.md) documentation. For building own applications
using the *cmcd*, refer to the [Developer Documentation](./dev.md).