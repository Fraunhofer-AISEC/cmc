# Intel TDX Setup

Describes the setup to run the CMC within Intel TDX Confidential VMs, also calles Trusted Domains (TDs)

All commands can be run in docker with `cmc-docker` prepended (e.g. `cmc-docker setup-cmc tdx`
instead of `setup-cmc tdx`). This omits installing prerequisites.

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

Everything can be built and installed according to the
[Build Documentation](./build-and-install.md).

## TDX services

Creating TDX quotes requires the Intel TDX Quote Generation Service (QGS) and the Intel
TDX Provisioning Certification Caching Service (PCCS), which we provide as docker containers:
```sh
run-tdx-pccs
run-tdx-qgs
```

## TDX Collateral

Verifying a TDX quote requires Intel collateral (TCB info, QE identity, PCK CRL and the Intel
root CA CRL). The CVM can fetch it directly from the Intel PCS or the PCCS (`endorsementMode`
`direct`), which requires the CVM to have internet access and to trust the public CAs.

Alternatively, the *estserver* proxies and caches the collateral, so that the CVM obtains
everything from a single address under a single CA. Configure the upstream service in the
[EST server configuration](../example-setup/configs/est-server-conf.json):
```json
{
    "vendorCache": "data/est-server-vendor-cache",
    "intelPcsUrl": "https://localhost:8081",
    "intelPcsRootCas": [ "data/pki/tdx-pccs-cert.pem" ]
}
```
`intelPcsUrl` is the address of the PCCS started via `run-tdx-pccs`, or
`https://api.trustedservices.intel.com` to use the Intel PCS directly. `intelPcsRootCas` are the
root CAs of that service, which are required for the certificate of the PCCS shipped with the CMC.
The collateral is cached in `vendorCache`. Cached collateral is refreshed every 24 hours and
continues to be served if the upstream service becomes unavailable.

The CVM then uses `cps` endorsement mode, which fetches both AMD and Intel collateral from the
*estserver*, and therefore requires neither internet access nor the public CAs:
```json
{
    "endorsementMode": "cps",
    "endorsementAddr": "https://10.0.2.2:9000/",
    "allowSystemCerts": false,
    "rootCas": [ "/var/ca.pem" ]
}
```
This configuration is identical for Intel TDX and AMD SEV-SNP CVMs.

## TDX Run

the `cmcd` and the `cmcctl` including their [configuration files](./run.md) must be installed
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

### Further documentation

Building and installing the individual components with various flags is described in the
[Build](./build-and-install.md) documentation. A more detailed description on how to configure and
run the components is described in the [Run](./run.md) documentation. For building own applications
using the *cmcd*, refer to the [Developer Documentation](./dev.md).