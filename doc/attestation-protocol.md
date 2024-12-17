# Attestation Protocol

The `attestedtls` package (as well as the `attestedhttps`, which builds upon `attestedtls`) relies
on TLS 1.3 to establish a secure channel. To avoid modifying existing TLS libraries, `attestedtls`
uses a post handshake channel binding to bind the attestation protocol to TLS 1.3 session.
To achieve this, the TLS master exporter secret is used as nonce in the client as well as
the server attestation report.

An additional peer caching mechanism ensures, that only the required metadata is sent to the peer
and described in the Section [Peer Cache Mechanism](#peer-cache-mechanism).

The simple attestation protocol that is run once the TLS 1.3 handshake completed is shown in the
following figure. For simplicity, a server-only attestation is shown. For a mutual attestation,
both sides must perform all steps:

![Attestation Protocol](./diagrams/atls-handshake.drawio.svg)

## Protocol Messages

The messages transferred as part of the attestation protocol have a simple header followed by
a [JSON](https://datatracker.ietf.org/doc/html/rfc8259) or
[CBOR](https://datatracker.ietf.org/doc/html/rfc8949) serialized payload:

The socket API uses a simple header followed by a serialized payload:

| Field   | Format            | Description           |
| ------- | ----------------- | --------------------- |
| Length  | 32-bit Big Endian | Length of the payload |
| Payload | JSON / CBOR       | Serialized payload    |

The `attest` field determines whether to perform mutual attestation, client-only attestation,
server-only attestation or no attestation and must match in all messages:

- `Attest_Mutual = 0`
- `Attest_Client = 1`
- `Attest_Server = 2`
- `Attest_None   = 3`

The following messages are defined:

## AtlsHandshakeRequest

The `AtlsHandshakeRequest` represents a request to initiate an aTLS handshake,
specifying the `attest` selection. For a description of the optional cached items,
see [Peer Cache Mechanism](#peer-cache-mechanism).

### JSON
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "attest": {
      "type": "string",
      "description": "The selected attestation type."
    },
    "cached": {
      "type": "array",
      "items": {
        "type": "string"
      },
      "nullable": true,
      "description": "Optional list of cached items."
    },
    "extendedReport": {
      "type": "boolean",
      "nullable": true,
      "description": "Whether to request an extended report."
    }
  },
  "required": ["attest"]
}
```

### CBOR
```
AtlsHandshakeRequest = {
    0: tstr,                         ; Attestation selection as a text string
    ? 1: [* tstr],                   ; Optional array of cached text strings
    ? 2: bool                        ; Optional boolean for extended report
}
```

## AtlsHandshakeResponse

The `AtlsHandshakeResponse` provides the response to an aTLS handshake request,
including `attest` selection, optional `error` messages, `report`, `metadata`, and cache misses.
For a description of the optional cache misses, see [Peer Cache Mechanism](#peer-cache-mechanism).

### JSON
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "attest": {
      "type": "string",
      "description": "The selected attestation type."
    },
    "error": {
      "type": "string",
      "nullable": true,
      "description": "An optional error message if the handshake failed."
    },
    "report": {
      "type": "string",
      "contentEncoding": "base64",
      "nullable": true,
      "description": "An optional attestation report."
    },
    "metadata": {
      "type": "object",
      "additionalProperties": {
        "type": "string",
        "contentEncoding": "base64"
      },
      "nullable": true,
      "description": "Optional metadata associated with the handshake."
    },
    "cacheMisses": {
      "type": "array",
      "items": {
        "type": "string"
      },
      "nullable": true,
      "description": "Optional list of cache misses."
    }
  },
  "required": ["attest"]
}
```

### CBOR
```
AtlsHandshakeResponse = {
    0: tstr,                         ; Attestation selection as a text string
    ? 1: tstr,                       ; Optional error message as a text string
    ? 2: bstr,                       ; Optional report as a byte string
    ? 3: { * tstr => bstr },         ; Optional metadata as a map of text strings to byte strings
    ? 4: [* tstr]                    ; Optional array of cache misses as text strings
}
```

## AtlsHandshakeComplete

The `AtlsHandshakeComplete` provides the final result of an aTLS handshake process,
indicating success or failure with an optional error message.

### JSON
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "success": {
      "type": "boolean",
      "description": "Indicates whether the handshake was successful."
    },
    "error": {
      "type": "string",
      "nullable": true,
      "description": "An optional error message if the handshake failed."
    }
  },
  "required": ["success"]
}
```

### CBOR
```
AtlsHandshakeComplete = {
    0: bool,                        ; Boolean indicating success
    ? 1: tstr                       ; Optional error message as a text string
}
```


## Peer Cache Mechanism

The attestation reports are self-contained, incorporating signed metadata items that represent the
reference software stack. However, for subsequent attestations, it is unnecessary to resend the
metadata if the verifier employs a mechanism to cache these items per peer, thereby reducing the
data transmitted as part of the attestation protocol. Consequently, the attestation report does not
embed the complete metadata items but instead includes only a hash for each metadata item, while the
items themselves are transmitted separately from the attestation report

The entire mechanism is optional. If the respective fields in the [Messages](#protocol-messages)
are left empty, simply the entire attestation report including all metadata is sent.

To uniquely identify peers, the TLS certificate fingerprint is used. With the
[aTLS Handshake Request](#atlshandshakerequest), the verifier can sent a list of hashes representing
metadata it has cached for the specific peer. The prover can then forward this list to the CMC
via the [Attestation Request](./cmcd-api.md#attestation-request). The CMC will only include
new metadata items into its [Attestation Response](./cmcd-api.md#attestation-response). If cached
items were not present, e.g. due to software updates, it will add them to the cache misses. These
can then be forwarded in the [aTLS Handshake Response](#atlshandshakeresponse) and further to the
peer CMC via the [Verification Request](./cmcd-api.md#verification-request). This optional mechanism
significantly reduces the amount of data transmitted during the attestation handshake.