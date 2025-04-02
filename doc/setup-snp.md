# AMD SEV-SNP Setup

Describes the setup to run the CMC within AMD SEV-SNP Confidential VMs.

## Prerequisites

Building the AWS Firmware (OVMF) to calculate the reference values for attestation of AWS AMD SEV-SNP
virtual machines requires [Nix](https://nixos.org/download/)

## SNP Setup

Creates the PKI and metadata for running the CMC within SNP Confidential VMs.
```sh
source env.bash
cmc-docker setup-cmc snp
```

The script calls [generate-rtm-manifest-snp](../bin/generate-rtm-manifest-snp), which calls the
`virtee/sev-snp-measure` tool to precompute the SNP measurement. The number of vCPUS, the
VMM-type and the SNP policy must be set within the script.

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

