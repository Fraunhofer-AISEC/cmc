# README

The `parsetdxmrs` tool parses the Intel TDX Runtime Measurement Registers (RTMRs) from the
CC eventlog ACPI table. If no input is specified, the file
`/sys/firmware/acpi/tables/data/CCEL` will be parsed.

## Build

```sh
go build
```

## Run

```sh
./parsetdxmrs -help # For usage info
```