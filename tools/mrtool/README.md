# README

## Overview

The *mrtool* precomputes or parses the values of Trusted Platform Module (TPM) Platform
Configuration Registers (PCRs), Intel TDX measurement registers (MRTD and RTMRs), as well as the
AMD SEV-SNP measurement.

Precomputation requires a reproducible build, which builds all artifacts running within the
(confidential) VM that shall be attested. This comprises the firmware, data passed to the VM,
such as ACPI tables, the kernel, the commandline, the initrd and user space programs.

If precomputation is not feasible, the tool can also parse the reference values from the
event logs of a known-good reference machine. The default locations of the event logs are:
- `/sys/kernel/security/tpm0/binary_bios_measurements` (TPM boot event log)
- `/sys/kernel/security/ima/binary_runtime_measurements` (TPM IMA runtime event log)
- `/sys/firmware/acpi/tables/data/CCEL` (TDX RTMR event log)

The reference values can be used for for remote attestation with the CMC framework or other
attestation mechanisms.

## Build

```sh
go build
```

## Usage

See `mrtool -help`.

## Examples

### Precomputation

Precomputing the reference values requires the built artifacts.

#### Precompute the TPM PCRs
```sh
mrtool precompute tpm \
    --mrs "0,1,2,3,4,5,6,7,8,9 \
    --ovmf OVMF.fd \
    --kernel kernel.bzImage" \
    --cmdline linux.cmdline
```

#### Precompute the IMA reference values

Precomputes the reference values for all files in the paths `/usr/bin`, `/usr/sbin` and `/usr/lib`:
```sh
mrtool precompute tpm \
    --mrs 10 \
    --path /usr/bin,/usr/sbin,/usr/lib \
    --template ima-ng \
```

#### Precompute the TDX RTMRs

Precompute MRTD, RTMR0-3, MRSEAM
```sh
mrtool precompute tdx \
    --mrs 0,1,2,3,4,5 \
    --tdxmodule intel_tdx_module.so \
    --ovmf OVMF.fd \
    --kernel kernel.bzImage \
    --cmdline linux.cmdline
```

#### Direct kernel boot and chainloading bootloaders

The measurements differ depending on whether the kernel is booted directly by the firmware or via
different bootloaders. The `mrtool` tries to automatically infer the boot path based on the
specified `--kernel` and `--bootloader` arguments. `--loadoptions {direct,chainloaded}` overrides
the inference.

- **Direct kernel boot** (`--kernel` alone), as performed by QEMU `-kernel`: the firmware loads
  the kernel itself and measures it into PCR4/RTMR1 before the `EV_EFI_GPT_EVENT`, as the boot
  device is not involved.
- **Chainloaded kernel** (`--kernel` together with `--bootloaders`), e.g. *systemd-boot* booting a
  BLS Type#1 entry: the kernel is only loaded once its bootloader runs and is therefore measured
  after it.
- **Unified kernel image**: A unified kernel image is measured section-wise by systemd-stub, see
  `--uki`.
- **GRUB**: GRUB measures the kernel itself and produces no `EV_IPL` even though a bootloader is
  involved, so it needs `--loadoptions direct`.

The distinction also decides how the UEFI LoadOptions carrying the kernel command line are
recorded in PCR9/RTMR2. EDK2 records the LoadOptions of a chainloaded kernel twice over the same
digest, once as `EV_IPL` and once as an `EV_EVENT_TAG` tagged `LOADED_IMAGE::LoadOptions`, whereas
a firmware-loaded kernel only gets the `EV_EVENT_TAG`. The initrd is measured into PCR9/RTMR2 as an
`EV_EVENT_TAG` tagged `Linux initrd` in both cases.

#### Precompute alternative reference values

Measurements that cannot be predicted can be precomputed as a set of mutually exclusive
alternatives, of which exactly one must match during verification. See
[Alternative Reference Values](../../doc/metadata.md#alternative-reference-values).

The TDX module a TD is launched on is chosen by the host, so accept any of several `MRSEAM`
hashes:
```sh
mrtool precompute tdx --mrs 5 --mrseam <hash>,<hash>,<hash>
```

The AMD SEV-SNP launch digest depends on the number of vCPUs, so accept any of several counts:
```sh
mrtool precompute snp --ovmf OVMF.fd --vcpus 1,2,4,8,16
```

Both flags also accept already precomputed digests (`--mrseam`, `--snp-digest`) and may be
repeated instead of using a comma-separated list.

### Parse Eventlogs

Parsing the event logs requires a reference machine. The `mrtool` uses the default locations,
other locations can be specified.

#### Parse the IMA eventlog

```sh
mrtool parse ima --mrs 10
```

#### Parse the TPM eventlog

PCR values for PCRs 0-9
```sh
mrtool parse tpm --mrs 0,1,2,3,4,5,6,7,8,9
```

## Parse the TDX CC eventlog

Parses the eventlog for RTMR0-3
```sh
mrtool parse tdx --mrs 1,2,3,4
```

### Parse a TPM Quote

Decode a signed TPMS_ATTEST TPM quote or a `[quote|sig]` blob produced by `azuretool get-vtpm-quote`
and print its fields. The format is auto-detected.

```sh
mrtool parse tpm-quote --in quote.bin
```
