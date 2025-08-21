# README

> :warning: **Note:** The tool is work in progress and not to be used in production!

For more tools, see also: https://github.com/Fraunhofer-AISEC/measured-boot-tools

## Overview

The *mrtool* parses or precomputes the values of Trusted Platform Module (TPM) Platform
Configuration Registers (PCRs), Intel TDX measurement registers (MRTD and RTMRs), as well as the
AMD SEV-SNP measurement.

The tool can be used to calculate the golden reference values for remote attestation
based on the built UEFI firmware, Linux kernel, kernel commandline, configuration parameters
and user space.

## Build

```sh
go build
```

## Usage

See `mrtool -help`.

## Examples

Parse the IMA eventlog and output reference values for PCR10
```sh
mrtool parse ima --mrs 10
```

Parse the TPM eventlog for PCRs 0-9 and output the eventlog, the final PCR values and the aggregated
PCR value over all PCRs
```sh
mrtool parse tpm --mrs 0,1,2,3,4,5,6,7,8,9
```

Parse the TDX CC eventlog for RTMR0-3
```sh
mrtool parse tdx --mrs 1,2,3,4
```

Calculate the `boot_aggregate` with an eventlog from a custom location. Then precompute the IMA
reference values for the `boot_aggregate` and for all files in the paths `/usr/bin`, `/usr/sbin`
 and `/usr/lib`.
```sh
boot_aggregate=$(mrtool parse tpm \
    --mrs 0,1,2,3,4,5,6,7,8,9 \
    --eventlog ./binary_bios_measurements \
    --print-eventlog=false \
    --print-aggregate=true \
    | jq -r .sha256)

mrtool precompute ima \
    --mrs 10 \
    --path /usr/bin,/usr/sbin,/usr/lib \
    --template ima-ng \
    --boot-aggregate "${boot_aggregate}"
```


