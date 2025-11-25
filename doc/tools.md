# Tools

Helper programs that support generating and signing reference values and interacting with trusted
and confidential computing hardware.

## backend

A simple HTTP web server with attached database for storing attestation results. This app is for
demonstration purposes only and not to be used in production.
For more information, see the [README](../tools/backend/README.md)

## mrtool

Parse and precompute reference hashes (TPM PCRs, Intel TDX RTMR/MRTD, AMD SEV-SNP measurements).
For more information, see the [README](../tools/mrtool/README.md)

## azuretool

Azure-specific helper for retrieving SNP/TDX attestation reports on Azure machines.

## tdxtool

Tool to generate and parse TDX quotes and metadata.

## snptool

Tool to generate and parse SNP attestation reports and metadata.