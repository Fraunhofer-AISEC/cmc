# Intel TDX Setup

Describes the setup to run the CMC within Intel TDX Confidential VMs, also calles Trusted Domains (TDs)

All commands can be run in docker with `cmc-docker` prepended (e.g. `cmc-docker setup-cmc tdx`
instead of `setup-cmc tdx`). This omits installing prerequisites.

## Prerequites

Install the measured-boot-tools as described in [prerequisites](./setup.md#prerequisites)

## TDX Setup

Creates the PKI and metadata for running the CMC within TDX Confidential VMs (also called
Trusted Domains (TDs)):
```sh
source env.bash
cmc-docker setup-cmc tdx
```

This script calls [generate-rtm-manifest-tdx](../bin/generate-rtm-manifest-tdx) and
[generate-os-manifest-tdx](../bin/generate-os-manifest-tdx). In both scripts, the
path to all artifacts required for precomputing the measurement registers must be set
(see [Intel TDX Manual Metadata Generation](./setup-tdx.md#intel-tdx-manual-metadata-generation))
for more information.

## TDX Build

To run within a CVM, everything can be [built as usual](./build.md).

## TDX services

Creating TDX quotes requires the Intel TDX Quote Generation Service (QGS) and the Intel
TDX Provisioning Certification Caching Service (PCCS), which we provide as docker containers:
```sh
run-tdx-pccs
run-tdx-qgs
```

## TDX Run

the `cmcd` and the `testtool` including their [configuration files](./run.md) must be installed
into the CVM image of your choice. Then the CMC can be run as described in
[Running the CMC](./run.md). Potentially you also want to create e.g. systemd services
to automatically run the components.


---


## Intel TDX Manual Metadata Generation

The reference values for Intel TDX consist of a fingerprint of the Intel Root CA certificate,
several measurement registers and CVM attributes.

Precomputing the measurement registers requires a reproducibly built OVMF, kernel, the kernel
cmdline and configuration parameters as input.

For a complete setup including precomputing all measurement registers, see
[generate-rtm-manifest-tdx](../bin/generate-rtm-manifest-sgx) and
[generate-os-manifest-tdx](../bin/generate-os-manifest-tdx).