# AMD SEV-SNP Setup

Describes the setup to run the CMC within AMD SEV-SNP Confidential VMs. Currently, QEMU and
AWS EC2 VMs are supported.

## Prerequisites

Building the AWS Firmware (OVMF) to calculate the reference values for attestation of AWS AMD SEV-SNP
virtual machines requires [Nix](https://nixos.org/download/)

## SNP Setup

Creates the PKI and metadata for running the CMC within SNP Confidential VMs. The CMC must be
[built and installed](./setup.md#build-and-install-the-cmc) first.
```sh
source env.bash
```

### QEMU VMs
```sh
# Builds the OVMF firmware
cmc-docker build-edk2

cmc-docker setup-cmc snp
```

### AWS EC2 VMs
```sh
# Builds the AWS OVMF firmware
cmc-docker build-ovmf-aws

cmc-docker setup-cmc snp --vmm-type ec2 --ovmf vm/images/OVMF-AWS.fd
```

The number of vCPUs can be set with `--vcpus`, see
[generate-metadata-snp](../bin/generate-metadata-snp).

## SNP Build

Everything can be built and installed according to the
[Build Documentation](./build-and-install.md).

## SNP Run

the `cmcd` and the `cmcctl` including their [configuration files](./run.md) must be installed
into the CVM. Then the CMC can be run as described in
[Running the CMC](./run.md). Potentially you also want to create e.g. systemd services
to automatically run the components.

---


## AMD SEV-SNP Manual Metadata Generation

Refer to the documentation of the AMD SNP
[virtee sev-snp-measure tool](https://github.com/virtee/sev-snp-measure).

An example can be found in the [precompute-rtm-manifest-snp](../bin/precompute-rtm-manifest-snp) script.

### Further documentation

Building and installing the individual components with various flags is described in the
[Build](./build-and-install.md) documentation. A more detailed description on how to configure and
run the components is described in the [Run](./run.md) documentation. For building own applications
using the *cmcd*, refer to the [Developer Documentation](./dev.md).