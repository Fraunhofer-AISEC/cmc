# README

## Overview

The *metatool* creates, signs and converts the attestation metadata used by the CMC framework
(see [metadata](../../doc/metadata.md)):

- `create`: creates metadata objects (`manifest`, `manifest-description`, `image-description`)
  and the policies embedded into them (`snp-policy`, `snp-version`, `tdx-policy`, `sgx-policy`)
- `sign`: signs metadata with one or more keys and certificate chains
- `convert`: converts metadata between JSON and CBOR

Reference values for manifests can be precomputed with the [mrtool](../mrtool/README.md).

## Build

```sh
go build
```

## Usage

See `metatool --help` and `metatool <command> --help`.

## Signing

Metadata can be signed during creation with `metatool create <type> --sign`, or after creation
with `metatool sign` (see `metatool sign --help`).

The signature algorithm is derived from the signing key and is the same for JSON (JWS) and
CBOR (COSE):

| Key                       | Algorithm                              |
| ------------------------- | -------------------------------------- |
| ECDSA P-256, P-384, P-521 | `ES256`, `ES384`, `ES512`              |
| Ed25519                   | `EdDSA`                                |
| RSA 2048, 3072, 4096      | `PS256`, `PS384`, `PS512` (RSASSA-PSS) |

Each key must match the public key of the leaf certificate of its chain. The signed output is
verified before it is written.

### External Signing

Keys that are not available as files, e.g. in a KMS or HSM, can sign in two steps. `--prepare`
writes the exact bytes to be signed (`--tbs-out`) and their digest under the signature algorithm
(`--digest-out`, not for Ed25519), derived from the leaf certificate. After signing with any tool,
`--attach` creates the signed metadata from the same `--in` and `--x5cs`:

```sh
metatool sign --prepare --in os.manifest --x5cs leaf.pem,ca.pem --digest-out os.digest

aws kms sign --key-id "$ARN" --message-type DIGEST --signing-algorithm ECDSA_SHA_256 \
    --message fileb://os.digest --query Signature --output text | base64 -d > os.sig

metatool sign --attach --in os.manifest --x5cs leaf.pem,ca.pem --signatures os.sig \
    --out os.manifest.signed
```

With a PKCS#11 token, the digest can be signed with `pkcs11-tool` instead. `--signature-format
openssl` makes it emit DER encoded ECDSA signatures:

```sh
pkcs11-tool --module "$PKCS11_MODULE" --login --id "$KEY_ID" --sign --mechanism ECDSA \
    --signature-format openssl -i os.digest -o os.sig
```

ECDSA signatures must be ASN.1 DER encoded, as emitted by AWS KMS and OpenSSL. RSA uses RSASSA-PSS
with a salt length equal to the hash length:

- AWS KMS: `--signing-algorithm RSASSA_PSS_SHA_256` (`_384`, `_512` for RSA 3072, 4096)
- OpenSSL: `openssl pkeyutl -sign -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:digest
  -pkeyopt digest:sha256` (`sha384`, `sha512`)
- PKCS#11: `pkcs11-tool --sign --mechanism RSA-PKCS-PSS --hash-algorithm SHA256 --mgf MGF1-SHA256
  --salt-len -1` (`SHA384`, `SHA512`)

Ed25519 signs the data itself, e.g. `openssl pkeyutl -sign -rawin -in os.tbs`. With multiple
signers, `--x5cs`, `--tbs-out`, `--digest-out` and `--signatures` take one entry per signer in the
same order. As for `--keys`, the output is verified before it is written.

For an example, refer to the example signing script:
```sh
sign-metadata json
```