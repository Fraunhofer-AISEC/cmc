# Platform Configuration

As a basic requirement, the *cmcd* must run on a Linux platform with TPM support enabled. The
platform must be capable of running a *Measured Boot* where each boot component measures the next
component into the respective TPM PCRs. Two approaches can be used, the Static Root of Trust for
Measurements (SRTM) and the Dynamic Root of Trust for Measurements (DRTM). Most platforms are
capable of performing an SRTM Measured Boot without further modifications, while a DRTM
measured boot requires hardware support and addtional software (such as
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

Note: Beside activating the respective kernel configurations, the components must also be
configured. *Systemd* is capable of configuring both dm-verity and the IMA. Furthermore,
custom software can be used and various user space tools for configuration exist. The
configurations depend highly on the used platform and distribution.
