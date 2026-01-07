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
