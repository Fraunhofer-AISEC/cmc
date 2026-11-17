# EST Server

The `estserver` enrolls the TPM attestation keys and the TLS keys of the CMC via EST (RFC 7030).
TPM attestation keys use an additional endpoint for credential activation. The server also serves
metadata and proxies the hardware vendor collateral (AMD KDS, Intel PCS).

## Enrollment Endpoints

All endpoints reside below `/.well-known/est`. The authentication methods of each enrollment
endpoint are configured in `est.auth` (`none`, `token`, `certificate`, `attestation`). An endpoint
without methods is disabled. `certificate` accepts TLS client certificates chaining to
`est.client_cas` (default: `est.ca_chain`), which must be set for this method. Neither the metadata
CAs (`trust.root_cas`) nor the system store are trusted for client authentication.

| Endpoint             | Enrolled key             | Authentication methods                        | Default                   |
| -------------------- | ------------------------ | --------------------------------------------- | ------------------------- |
| `/simpleenroll`      | TLS key                  | `none`, `token`, `certificate`, `attestation` | `attestation`             |
| `/simplereenroll`    | TLS key                  | `certificate`, `attestation`                  | `certificate,attestation` |
| `/tpmactivateenroll` | TPM attestation key (AK) | `none`, `token`, `certificate`                | `token`                   |

A request is served if any of the configured methods succeeds. `/simplereenroll` renews the TLS
client certificate and requires all configured methods to succeed, so `certificate` is mandatory
and `attestation` additionally requires fresh evidence in the CSR. `est.client_cas` must contain
the EST CA. Subject and SANs of the CSR must be identical to the client certificate
(RFC 7030 4.2.2), a new key is allowed. The certificate policies are derived from the fresh
attestation result only.

`/tpmactivateenroll` performs TPM credential activation, which proves that the AK resides in the
TPM of the EK. `/csrattrs` requests attestation evidence in the CSR if `/simpleenroll` is
configured with `attestation`.

### Evidence in the CSR

`/simpleenroll` and `/simplereenroll` accept evidence in the CSR as specified by
draft-ietf-lamps-csr-attestation (`id-aa-attestation` attribute):

- **CMC attestation report** (CMW record): verified with the hash of the CSR public key as nonce.
  `attestation` authenticates the client with it. A CSR with a report requires `attestation` to be
  configured, otherwise the request is rejected as configuration mismatch. An invalid report
  rejects the request.
- **TPM key evidence** (`tcg-attest-tpm-certify`): TPM2_Certify of the CSR key by the AK, the AK
  certificate chain is part of the attestation bundle, leaf first. The evidence is verified regardless of
  the authentication methods and is accepted if the AK certificate chains to the root of the EST CA
  chain and contains `tcg-kp-AIKCertificate`, i.e., was issued via `/tpmactivateenroll`. Other AKs,
  e.g., self-signed vTPM AKs (`--tpm-endorsement self`), are only accepted if the client
  authenticated via `attestation` and the AK signed the TPM quote of the report.

## Certificate Profiles

The extended key usages and the certificate policies (RFC 5280) of an issued certificate state
what the key may be used for and how it was enrolled:

| Endpoint             | Extended key usages        | Certificate policies       |
| -------------------- | -------------------------- | -------------------------- |
| `/tpmactivateenroll` | `tcg-kp-AIKCertificate`    | none                       |
| `/simpleenroll`      | `serverAuth`, `clientAuth` | attestation level and TEEs |
| `/simplereenroll`    | `serverAuth`, `clientAuth` | attestation level and TEEs |

The attestation level and TEE OIDs are only issued if the client authenticated via `attestation`.
`tcg-kp-AIKCertificate` (2.23.133.8.3, TCG EK Credential Profile) marks AK certificates. The
verifier only accepts TPM quotes signed by an AK whose certificate carries it, so that TLS
certificates from the same CA cannot sign quotes.

### Certificate Policy OIDs

The certificate policies state the attestation level the key was enrolled with. They support the
[RATS passport model](./attestation-models.md): the prover is attested once during enrollment, and
relying parties then use ordinary TLS and check the policies of the peer certificate instead of
attesting the peer.

All policy OIDs reside below a base arc, which is configured via `cert_policy.arc`
(`--cert-policy-arc`). The `estserver` and the relying parties must use the same arc.

| OID         | Meaning                                                        |
| ----------- | -------------------------------------------------------------- |
| `<arc>.1.1` | Key enrolled with software-based attestation (`sw` driver)     |
| `<arc>.1.2` | Key enrolled with hardware-based attestation                   |
| `<arc>.2.1` | TPM verified during enrollment                                 |
| `<arc>.2.2` | AMD SEV-SNP verified during enrollment                         |
| `<arc>.2.3` | Intel TDX verified during enrollment                           |
| `<arc>.2.4` | Intel SGX verified during enrollment                           |

The level OID corresponds to the `attestLevel` of the attestation result (0 `none`, 1 `software`, 2
`hardware`), i.e., the level the verified evidence reached. A certificate carries one TEE OID for
each verified hardware trust anchor, e.g., SNP and TPM for an Azure SNP CVM. Keys enrolled without
attestation, i.e., authenticated with `none`, `token` or `certificate`, carry no policy OID, which corresponds to attestation level `none`.

The default arc `2.25.130688535707081957510737207999343475614` is a UUID-based OID (ITU-T X.667),
which requires no registration. Production deployments should use an arc below their own private
enterprise number (PEN), e.g. `1.3.6.1.4.1.<PEN>.1`.

Example of a TLS certificate enrolled via `/simpleenroll` with attestation in an SNP CVM:

```
X509v3 Certificate Policies:
    Policy: 2.25.130688535707081957510737207999343475614.1.2
    Policy: 2.25.130688535707081957510737207999343475614.2.2
```

The policies are a statement about the time of enrollment. They do not provide freshness, so
attested certificates should be short-lived. The lifetime of all issued certificates is configured
via `est.cert_validity` (`--cert-validity`).

### Enforcement

`cmcctl` enforces a minimum attestation level on the TLS certificate of the peer, e.g., on a
connection without attestation. All hardware trust anchors are treated as equal, the TEE OIDs are
informational:

```sh
# Require a TLS certificate enrolled with hardware-based attestation
cmcctl dial --attest none --peer-cert-level hardware
```

```toml
[atls]
peer_cert_level = "hardware"  # none, software or hardware
```

The certificate chain must be validated, so this option cannot be combined with
`atls.attestation_only_trust`. On the server side, it requires mutual TLS.

Other applications can use the `certpolicy` package, whose `Tree.VerifyConnection` returns a
`tls.Config.VerifyConnection` callback. Only the policies of the leaf certificate are checked, as
the Go standard library enforces certificate policies only if a CA in the chain requires an
explicit policy. OpenSSL enforces them with `openssl verify -policy <oid> -explicit_policy`, which
requires intermediate CAs to carry the policies or `anyPolicy`.
