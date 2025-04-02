# TPM Setup

Describes the setup to run the CMC on platforms with a Trusted Platform Module (TPM)

## Prerequisites

You need a machine with a TPM and `/dev/tpmrm0` or `/dev/tpm0` present. This is the case for most
desktop and server platforms. Alternatively, you can test the CMC in a VM with an attached
software TPM.

> :warning: **Note:** You should run the CMC only for testing on a development machine, or inside
> a Virtual Machine (VM). The software directly interacts with the TPM.

## TPM Setup

Creates the PKI and metadata for running the CMC on TPM platforms
```sh
source env.bash
cmc-docker setup-cmc tpm
```

## TPM Build

Everything can be [built as usual](./build.md).

## TPM Run

the `cmcd` and the `testtool` including their [configuration files](./run.md) must be installed
into the TPM platform or VM with attached swTPM. Then the CMC can be run as described in
[Running the CMC](./run.md).


---


## TPM Manual Metadata Generation

The reference values can either be parsed on a good reference platform in a secure environment,
or they can be precomputed based on the built software artifacts of a computing platform (e.g.,
within a build-system such as *Yocto* or *Buildroot*). Tools for parsing and precomputing
are available as open source [tpm-pcr-tools](https://github.com/Fraunhofer-AISEC/tpm-pcr-tools).

Complete examples can be found in the [generate-rtm-manifest-tpm](../bin/generate-rtm-manifest-tpm),
[generate-os-manifest-tpm](../bin/generate-os-manifest-tpm),
[generate-app-manifest-tpm](../bin/generate-app-manifest-tpm) and
[generate-app-manifest-live-tpm](../bin/generate-app-manifest-live-tpm) scripts.

### Parsing the Reference Values

Parse the values of the RTM PCRs from the kernel's binary bios measurement log
```sh
sudo parse-srtm-pcrs -p 0,1,2,3,4,5,6,7 -f json
```
Then insert those values into the json `referenceValues` array in the RTM manifest.

Parse the values of the OS PCRs from the kernel's binary bios measurement log:
```sh
sudo parse-srtm-pcrs -p 8,9,11,12,14,15 -f json
```
Then insert those values into the json `referenceValues` array in the OS manifest.

For the host applications, if the kernel's Integrity Measurement Architecture (IMA) is activated:
```sh
sudo parse-ima-pcr
```
Then insert those values into the json `referenceValues` array in an app manifest.

For OCI containers, we currently use a patched `runc` binary, which can output the reference
values of containers launched by different container engines (docker, podman, containerd, runc).

The script [generate-container-manifest](../bin/generate-container-manifest) can create a
manifest with these reference values, e.g.:
```sh
generate-container-manifest ubuntu:24.04 . ../cmc docker
```

### Calculating the Reference Values

This currently only works for QEMU VMs with OVMF and a Linux kernel.

Calculate the RTM Manifest reference values:
```sh
calculate-srtm-pcrs \
      --format json \
      --pcrs 0,1,2,3,6,7 \
      --eventlog \
      --kernel "linux-kernel.bzImage" \
      --ovmf "OVMF.fd" \
      --config "calculate-pcrs.cfg" \
```
Then insert those values into the json `referenceValues` array in the RTM Manifest.

Calculate the OS Manifest reference values:
```sh
calculate-srtm-pcrs \
    --kernel "linux-kernel.bzImage" \
    --cmdline "linux-commandline" \
    --ovmf "OVMF.fd" \
    --format json \
    --pcrs "4,5,8,9,11,12,13,14,15" \
    --eventlog \
```
Then insert those values into the json `referenceValues` array in the OS Manifest.

For the host applications, if the kernel's Integrity Measurement Architecture (IMA) is activated:
```sh
# In this case, use PCR10 and the IMA ima-ng template for all folders containing binaries and libs
sudo calculate-ima-pcr -t 10 -i ima-ng -p /usr/bin -p /usr/sbin -p /usr/lib
```
Then insert those values into an app manifest.

## Platform Configuration

The *cmcd* must run on a Linux platform with TPM support enabled. The
platform must be capable of running a *Measured Boot* where each boot component measures the next
component into the respective TPM PCRs. Two approaches can be used, the Static Root of Trust for
Measurements (SRTM) and the Dynamic Root of Trust for Measurements (DRTM). Most platforms are
capable of performing an SRTM Measured Boot without further modifications, while a DRTM
measured boot requires hardware support and additional software (such as
[Intel TXT](https://www.intel.com/content/www/us/en/developer/articles/tool/intel-trusted-execution-technology.html?wapkw=txt),
[Intel SINIT ACM](https://software.intel.com/content/www/us/en/develop/articles/intel-trusted-execution-technology.html),
and [tboot](https://sourceforge.net/projects/tboot/)).

Furthermore, *Secure Boot* should be enabled and the platform should only run signed and
verified components. It is advisable to run a minimal, hardened Linux distribution for server or
container environments.

## BIOS/UEFI Configuration

For SRTM, only the TPM must be activated in the BIOS configuration.

DRTM requires processor hardware support and thus additional configurations. For Intel processors,
the following capabilities must be activated:
- Activate Intel TPM
- Activate Intel VT, Intel VT-d
- Activate Intel TXT
- Activate Administrator Password
- Clear TPM

## Kernel Configuration

Running the *cmcd* for testing purposes only requires TPM support, which is enabled by default
on most distributions:

- CONFIG_TCG_TPM

Depending on the platform and use case (e.g. to reach IDS Trust or Trust+ Level), further
configurations might be required:

The kernel should only load signed kernel modules:

- CONFIG_MODULE_SIG
- CONFIG_MODULE_SIG_FORCE
- CONFIG_MODULE_SIG_ALL
- CONFIG_MODULE_SIG_SHA256
- CONFIG_MODULE_SIG_HASH

The initramfs should be signed and appended to the kernel to be included into the measured boot:

- CONFIG_INITRAMFS_SOURCE

The Integrity Measurement Architecture (IMA) can be activated to measure firmware, kernel modules
and, if desired, also binaries running in the root namespace:

- CONFIG_INTEGRITY
- CONFIG_INTEGRITY_SIGNATURE
- CONFIG_INTEGRITY_ASYMMETRIC_KEYS
- CONFIG_IMA
- CONFIG_IMA_APPRAISE
- CONFIG_IMA_APPRAISE_MODSIG
- CONFIG_IMA_MEASURE_PCR_IDX
- CONFIG_IMA_SIG_TEMPLATE
- CONFIG_IMA_DEFAULT_HASH_SHA256
- CONFIG_IMA_DEFAULT_HASH
- CONFIG_IMA_WRITE_POLICY
- CONFIG_IMA_READ_POLICY
- CONFIG_IMA_DEFAULT_TEMPLATE
- CONFIG_IMA_LOAD_X509
- CONFIG_IMA_X509_PATH
- CONFIG IMA_QUEUE_EARLY_BOOT_KEYS
- CONFIG_SYSTEM_BLACKLIST_KEYRING
- CONFIG_KEYS
- CONFIG_MODULE_SIG_KEY
- CONFIG_SYSTEM_TRUSTED_KEYS
- CONFIG_INTEGRITY_TRUSTED_KEYRING

*dm-verity* can be activated and used in combination with a read-only rootfs (e.g. SquashFS) to
measure and verify the rootfs and integrate it into the measured boot:

- CONFIG_BLK_DEV_DM
- CONFIG_DM_INIT
- CONFIG_DM_VERITY
- CONFIG_DM_VERITY_VERIFY_ROOTHASH_SIG
- CONFIG_DM_VERITY_FEC
- CONFIG_SQUASHFS

## User space configuration

Note: Beside activating the respective kernel configurations, the subsystems must also be
configured. *Systemd* is capable of configuring both dm-verity and IMA.