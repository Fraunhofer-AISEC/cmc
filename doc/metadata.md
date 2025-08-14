# Metadata

Metadata in the form of *Manifests* and *Descriptions* is used to described the expected state
of the platform including all references values (hashes) of the expected software.

The entire set of metadata is put together into an *Attestation Report*. The overall architecture
and the *Attestation Report* are described in [Architecture](./architecture.md). Read the
architecture section first for a better understanding.

## Serialization Format

The metadata can be serialized to [JSON](https://datatracker.ietf.org/doc/html/rfc8259)
and signed via [JSON Web signatures (JWS)](https://www.rfc-editor.org/rfc/rfc7515.html), or to
[CBOR](https://datatracker.ietf.org/doc/html/rfc8949) and signed via
[CBOR Object Signing and Encryption (COSE)](https://datatracker.ietf.org/doc/html/rfc8152).

As CBOR is a binary serialization format, the serialized data is not human-readable. Therefore, the
metadata templates are always in JSON. A [converter](../tools/metaconv/) is provided to convert the
metadata files to CBOR before signing them (see [Setup](./setup.md)).

## Metadata Templates

The example setup (folder `cmc/example-setup`) contains templates for the required metadata files
in JSON.

- **device.description.json**: Metadata describing the overall platform
- **manifest.description.json**: Embedded into device description, describes an instance of a
manifest (i.e., a software layer or application)
- **manifest.json**: Template for a manifest containing reference values for a specific software
layer or single application
- **company.description.json**: Optional, metadata describing the operater of the computing platform
- **device.config.json**: Signed local device configuration, contains e.g. the parameters for
the Certificate Signing Requests for the attestation and identity keys

## Populating Metadata

Metadata can be generated and populated manually or automatically from the templates. Refer to
e.g. [generate-rtm-manifest-tpm](../bin/generate-rtm-manifest-tpm) for an example on how to
populate the metadata automatically via `jq` and the
[measured-boot-tools](https://github.com/Fraunhofer-AISEC/measured-boot-tools).

### Manifest Names

Manifest names, descriptions and validity can be chosen freely. However, manifests must be linked
via the `baseLayer` property: A single root manifest references itself (i.e. its `name`) in the
baseLayer. This is usually the manifest containing the Root of Trust, e.g. the measurement of the
(virtual) firmware (PCR0 - PCR7, Intel TDX MRTD, AMD SEV-SNP Measurement). Subsequent manifests
must reference compatible base layers, e.g. the second manifest could contain the kernel and OS
reference values and references the root manifest and further manifests contain host
applications and containers.

### Reference Values

The reference values, i.e. the hashes of software allowed to run on the platform are the core of
each manifest. Ideally, the reference values are generated from the artifacts of a reproducible
build comprising all software running on a platform. The tools
- [calculate-srtm-pcrs](https://github.com/Fraunhofer-AISEC/measured-boot-tools/tree/main/calculate-srtm-pcrs)
- [calculate-ima-pcr](https://github.com/Fraunhofer-AISEC/measured-boot-tools/tree/main/calculate-ima-pcr)
- [calculate-tdx-mr](https://github.com/Fraunhofer-AISEC/measured-boot-tools/tree/main/calculate-tdx-mrs)
- [calculate-snp-mr](https://github.com/Fraunhofer-AISEC/measured-boot-tools/tree/main/calculate-snp-mr)

can be used to generate the reference values in the correct format.

If it is not possible to precompute all reference values, they can be parsed from the UEFI
(`/sys/kernel/security/tpm0/binary_bios_measurements`),
IMA (`/sys/kernel/security/ima/binary_runtime_measurements`) and
CCEL (`/sys/firmware/acpi/tables/data/CCEL`) event logs of a known-good reference platform
with the following tools:
- [parse-srtm-pcrs](https://github.com/Fraunhofer-AISEC/measured-boot-tools/tree/main/parse-srtm-pcrs)
- [parse-ima-pcr](https://github.com/Fraunhofer-AISEC/measured-boot-tools/tree/main/parse-ima-pcr)
- [parsetdxmrs](https://github.com/Fraunhofer-AISEC/cmc/tree/main/tools/parsetdxmrs)

See the metadata generation and precomputation scripts in the [bin](../bin/) folder for various
examples.

## Signing Metadata

As soon as the platform-specific metadata has been generated, it must be signed.

By default, the metadata is in JSON format. If the demo-setup is used, the metadata can
be signed with:
```sh
sign-metadata json
```
This signs all metadata in `data/metadata-raw` and puts it in `data/metadata-signed`. If
`CBOR` serialization shall be used, simply replace `json` with `cbor`.

If an own setup and PKI are used, metadata can be signed with the `metasign` tool:
```sh
metasign -in <metadata.json> -out <metadata-signed.json> -keys <private-key(s)> -x5cs <certificate-chain(s)>
```

If the CMC shall work with CBOR metadata, first convert the metadata and then sign as described
above:
```sh
# Convert JSON to CBOR using the converter-tool
metaconv -in <input-file>.json -out <output-file.cbor> -inform json -outform cbor
```

## Parsing Metadata

The unsigned JSON metadata can simply be viewed in any editor or via `jq`:
```sh
jq . metadata.json
```

Signed metadata in JWS format has `base64`-formatted payload. Inspecting the metadata can be done
with `jq` and `base64`:
```sh
jq -r .payload | base64 -di | jq .
```

Usually, all relevant data is displayed in the `Verification Result`, which is produced on every
attestation. However, if you want to inspect the `Attestation Report` itself, this can also be done
using various bash tools:

Display the raw TPM quote:
```sh
jq .payload attestation-report \
    | base64 -di \
    | jq  .measurements[0].evidence \
    | base64 -di \
    | xxd
```

Display the certificate that was used to sign the evidence:
```sh
jq -r '.payload' attestation-report \
    | base64 -di | jq '.measurements[0].certs[0]' \
    | base64 -di \
    | openssl x509 -noout -text -inform DER
```
