## ACME Server

This implementation of an acme server implements the basic structures necessary to implement the protocol.

It stores the entire client state in memory and does not persist it across restarts.

The server supports attestation procedures, but will not tag or in any other way flag the certificates as being authorized by a successful attestation. In the case of an attestation challenge being used, the server does not validate that the client has control over the identifier.

The corresponding ACME client is implemented in [`provision/acme`](../../provision/acme/) and is used by the cmcd.

### Operating modes

The server runs in one of two modes (selected via usage of `--upstream`):

- **CA mode** (default): the server signs finalized orders itself with a local issuing CA. If no CA certificate and key are provided, an ephemeral CA is generated at startup.
- **Proxy mode** (`--upstream <directory-url>`): the server does not sign anything itself. At startup it connects to the upstream ACME server, fetches its directory and registers (or looks up) an account with the configured account key. Clients still authenticate to the proxy via the `cmc-*` challenges; finalized orders are relayed to the upstream server, which issues the certificate.

### Usage

```sh
acmeserver [options] --port <port>
```

If a TLS certificate and key are provided, the server serves the ACME protocol over HTTPS, otherwise it uses HTTP.

|Flag      |Description  |
|----------|-------------|
| `--port` | Port the server listens on (required) |
| `--cert` | Path to TLS certificate for HTTPS (optional) |
| `--key` | Path to TLS key for HTTPS (optional) |
| `--metadata-cas` | Path to PEM file with trusted metadata root CAs (required for `cmc-software-attest-01` and `cmc-tpm-certify-01`) |
| `--ca-cert` | CA mode: path to CA certificate used to sign issued certificates (ephemeral CA if omitted) |
| `--ca-key` | CA mode: path to CA private key used to sign issued certificates (ephemeral CA if omitted) |
| `--upstream` | Proxy mode: directory URL of the upstream ACME server |
| `--upstream-account-key` | Proxy mode: path to PEM-encoded EC private key for the upstream account, to reuse account; created if missing; ephemeral if omitted |
| `--upstream-contact` | Proxy mode: contact URL (e.g. `mailto:ops@example.com`) registered with the upstream account; may be repeated |
| `--upstream-ca` | Proxy mode: PEM file with root CAs trusted for the TLS connection to the upstream server (system roots if omitted) |

`--ca-cert`/`--ca-key` and `--upstream` are mutually exclusive.

Examples:

```sh
# Simple HTTP test server with ephemeral CA
acmeserver --port 8080

# HTTPS server with provided issuing CA and attestation challenges available
acmeserver --port 443 --cert server.crt --key server.key --ca-cert ca.crt --ca-key ca.key --metadata-cas metadata-cas.pem

# Proxy mode
acmeserver --port 443 --cert server.crt --key server.key --metadata-cas metadata-cas.pem --upstream https://some-acme.org/directory --upstream-account-key ./account.key --upstream-contact mailto:ops@example.com
```

The ACME directory is served at the server root (`/`).

Orders expire after 4 hours. In CA mode, issued certificates are valid for 90 days and the server returns both the new certificate and the CA certificate. In proxy mode, the upstream CA determines the certificate lifetime and chain.

Depending on the mode, the finalization may put the order in the `processing` state, while it performs the authorization against the upstream ACME server.

### Challenges

The server provides one authorization for each `dns` identifier in an order. Each authorization offers the following challenges, of which at least one needs to be fulfilled: `cmc-software-attest-01`, `cmc-tpm-certify-01`, and `cmc-simple-01`.

`cmc-simple-01`:

A custom challenge to provide the simple enrollment. The client responds with a payload containing the key authorization as string as `authorization`.

`cmc-software-attest-01`:

A custom challenge mimicing the cmc, which validates a cmc attestation report. The client responds with a payload containing the base64url encoded fields `report` (the attestation report) and `csr` (the DER-encoded CSR). The report must contain a nonce derived from the CSR and the ACME account key. If the report can be validated, the public key of the CSR is stored. The finalization will only create certificates for this exact key.

`cmc-tpm-certify-01`:

An extension of `cmc-software-attest-01`, which also proves that the certified key (IK) lives in the same TPM as the attestation key (AK), which signed the report. In addition to `report` and `csr`, the payload contains the base64url encoded fields `akPublic`, `ikPublic`, `ikCreateData`, `ikCreateAttestation`, and `ikCreateSignature`. Similarily to `cmc-software-attest-01`, the attested key is also bound to the order for the finalization.

### Open Topics

As of now, the server does not serve a real ToS, just a simple static text.

In proxy mode, the ToS of the upstream is silently accepted.

Proxy mode does not yet implement any upstream challenge solving.
