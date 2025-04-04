# README

This tool extracts an UEFI firmware volume (FV) from dumped guest memory.

During guest initialization, QEMU extracts the firmware volumes and places them in guest memory. The
volumes are then measured into the PCRs or TDX MRs. This tool can be used to spot differences between
calculated measurements and the actual measurements.

## Build

```sh
go build
```

## Usage

Dump QEMU guest memory of a running VM through switching to QEMU monitor mode (CTRL+A,C):
```sh
dump-guest-memory /path/to/output/file
```

Run `extractfv` tool to extract the FV from the dumped memory:
```
extractfv -ref <reference-file> -out <extracted-fv> -in <qemu-dumped-memory> -fv <peifv|dxefv> [-refsize <num-bytes>]
```