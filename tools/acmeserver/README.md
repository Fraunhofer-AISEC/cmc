## ACME Server

This implementation of an acme server implements the basic structures necessary to implement the protocol.

It stores the entire client state in memory and does not persist it across restarts.

The server supports attestation procedures, but will not tag or in any other way flag the certificates as being authorized by a successful attestation. In the case of an attestation challenge being used, the server does not validate that the client has control over the identifier.

The corresponding ACME client is implemented in [`provision/acme`](../../provision/acme/) and is used by the cmcd.

### Usage

```sh
acmeserver [options] --port <port>
```

If a TLS certificate and key are provided, the server serves the ACME protocol over HTTPS, otherwise it uses HTTP. If no CA certificate and key are provided, an ephemeral CA is generated at startup. It is then used to sign the validated requests.

|Flag      |Description  |
|----------|-------------|
| `--port` | Port the server listens on (required) |
| `--cert` | Path to TLS certificate for HTTPS (optional) |
| `--key` | Path to TLS key for HTTPS (optional) |
| `--ca-cert` | Path to CA certificate used to sign issued certificates (ephemeral CA if omitted) |
| `--ca-key` | Path to CA private key used to sign issued certificates (ephemeral CA if omitted) |
| `--metadata-cas` | Path to PEM file with trusted metadata root CAs (required for `cmc-software-attest-01` and `cmc-tpm-certify-01`) |
| `--http01-port`  | Port used to fetch `http-01` key authorizations from clients (default: 80) |

Examples:

```sh
# Simple HTTP test server with ephemeral CA
acmeserver --port 8080

# HTTPS server with provided issuing CA and attestation challenges available
acmeserver --port 443 --cert server.crt --key server.key --ca-cert ca.crt --ca-key ca.key --metadata-cas metadata-cas.pem
```

The ACME directory is served at the server root (`/`).

Orders expire after 4 hours. Issued certificates are valid for 90 days and the server returns both the new certificate and the CA certificate.

### Challenges

The server provides one authorization for each `dns` identifier in an order. Each authorization offers the following challenges, of which at least one needs to be fulfilled: `cmc-software-attest-01`, `cmc-tpm-certify-01`, and `http-01`.

`http-01`:

The standard HTTP challenge. The client responds with an empty payload (`{}`) and must serve the key authorization at `http://<identifier>/.well-known/acme-challenge/<token>` on the port specified via the the arguments.

`cmc-software-attest-01`:

A custom challenge modelled around the cmc, which validates a cmc attestation report. The client responds with a payload containing the base64url encoded fields `report` (the attestation report) and `csr` (the DER-encoded CSR). The report must contain a nonce derived from the CSR and the ACME account key. If the report can be validated, the public key of the CSR is stored. The finalization will then only create certificates for this exact key.

`cmc-tpm-certify-01`:

An extension of `cmc-software-attest-01`, which also proves that the certified key (IK) lives in the same TPM as the attestation key (AK), which signed the report. In addition to `report` and `csr`, the payload contains the base64url encoded fields `akPublic`, `ikPublic`, `ikCreateData`, `ikCreateAttestation`, and `ikCreateSignature`. Similarily to `cmc-software-attest-01`, the attested key is also bound to the order for the finalization.
