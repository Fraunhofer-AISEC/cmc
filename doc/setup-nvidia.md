# NVIDIA CC GPU Setup

Describes the setup to attest NVIDIA GPUs running in Confidential Computing (CC) mode.

The NVIDIA driver attests the state of the GPU: firmware measurements, device identity, and the
driver and VBIOS versions it reports. Reports containing NVIDIA evidence must be combined with a
CPU trust anchor such as SEV-SNP or TDX.

## Prerequisites

- The driver currently supports NVIDIA Hopper GPUs only.
- The GPU must be in CC mode, so that it produces signed attestation reports.
- The NVIDIA driver must be installed. The CMC driver `dlopen`s `libnvidia-ml.so.1`, falling
  back to `libnvidia-ml.so`, so the library must be present to run.

## NVIDIA Build

The driver uses cgo and is Linux-only. It is included in a default build. For a `nodefaults`
build, enable it with the `nvidia` tag:

```sh
go build -tags nodefaults,socket,snp,nvidia
```

Everything else can be built and installed according to the
[Build Documentation](./build-and-install.md).

> Note: `CGO_ENABLED=0` excludes the driver from any build, including a default one.

## NVIDIA Run

Add the driver to the `drivers` list of the `cmcd` [configuration file](./run.md):

```toml
[attestation]
drivers = ["snp", "nvidia"]
```

One evidence element is produced per GPU found on the system.

### Supplemental measurements

Some policy checks rely on measurements that NVML reports but which are *not* covered by the
GPU's signed attestation report, such as the inforom object versions, the GSP firmware mode and
the MIG mode. Collecting them can be configured via:

```toml
[attestation]
extended_checks = true
```
Set `requireSupplementalEvidence` in the policy to reject reports that omit supplemental measuremts.

### Caches

The driver caches the device certificate chains in `nvidia_certs.json` within the configured
storage folder (`storage.data`), so that subsequent starts do not have to query the hardware,
and the fetched RIMs and OCSP responses in the `vendor-cache/nvidia` subfolder of it.

Collateral is refetched when the earliest OCSP `NextUpdate` has passed. If no storage folder is
configured, the data is only cached in memory and thus fetched again on every start.

## NVIDIA Metadata Generation

The GPU manifest carries a NVIDIA policy that states what the verifier must enforce. Create one
with `metatool`, then reference it from a manifest:

```sh
metatool create nvidia-policy \
  --device-ca-fingerprints "102bf659d5419614c9d8e6aecebc80454eb26b1df6a769ac720b9a690b167b48" \
  --rim-ca-fingerprints "12977b5115acb0381179279fffeb5a8c4d264971ebb32298023a465fa41df5d1" \
  --vbios-min-version "96.00.74.00.11" \
  --driver-min-version "595.71.05" \
  --allowed-architectures HOPPER \
  --require-ocsp-for-rims \
  --out gpu.policy.json

metatool create manifest \
  --name "de.test.gpu" \
  --nvidia-policy gpu.policy.json \
  ...
```

A complete example is in the [generate-gpu-rtm-manifest](../bin/generate-gpu-rtm-manifest)
script. `metatool create nvidia-policy --help` lists every check, including the supplemental ones
described above.

## What is verified

For each GPU evidence element the verifier:

1. rejects an unrecognised architecture, and applies the architecture allowlist and the UUID
   denylist, which is done first so that a known-bad device costs no cryptography,
2. anchors the device certificate chain in a device root CA whose fingerprint the policy pins,
   *before* any signature is checked against its leaf,
3. verifies the attestation report signature with the anchored leaf key,
4. parses the SPDM request and response, and checks the nonce the report echoes,
5. checks the report's SPDM measurement blocks against the reference values from the driver and
   VBIOS RIMs, whose signing chains are anchored in a RIM root CA whose fingerprint the policy
   pins,
6. checks the OCSP revocation status of the device chain, and of the RIM chains if the policy
   requires it, and
7. applies the supplemental and version policy checks.

### Further documentation

Building and installing the individual components with various flags is described in the
[Build](./build-and-install.md) documentation. A more detailed description on how to configure and
run the components is described in the [Run](./run.md) documentation. For building own applications
using the *cmcd*, refer to the [Developer Documentation](./dev.md).
