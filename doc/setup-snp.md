# AMD SEV-SNP Setup

Describes the setup to run the CMC within AMD SEV-SNP Confidential VMs. Currently, QEMU and
AWS EC2 VMs are supported.

## Prerequisites

Building the AWS Firmware (OVMF) to calculate the reference values for attestation of AWS AMD SEV-SNP
virtual machines requires [Nix](https://nixos.org/download/)

## SNP Setup

Creates the PKI and metadata for running the CMC within SNP Confidential VMs.
```sh
source env.bash
```

### QEMU VMs
```sh
cmc-docker setup-cmc snp
```

### AWS EC2 VMs
```sh
cmc-docker snp-ec2-setup

cmc-docker generate-metadata-snp [--vcpus NUM] [--vmm-type ec2]
```

## SNP Build

To run within a CVM, everything can be [built as usual](./build.md).

## SNP Run

the `cmcd` and the `testtool` including their [configuration files](./run.md) must be installed
into the CVM. Then the CMC can be run as described in
[Running the CMC](./run.md). Potentially you also want to create e.g. systemd services
to automatically run the components.

---


## AMD SEV-SNP Manual Metadata Generation

Refer to the documentation of the AMD SNP
[virtee sev-snp-measure tool](https://github.com/virtee/sev-snp-measure).

An example  can be found in the [generate-rtm-manifest-snp](../bin/generate-rtm-manifest-snp) script.

