# CMC API

This document described the *cmcd* APIs. For documentation, where this API is used, refer to
[Architecture](./architecture.md). The *cmcd* provides a [gRPC](https://grpc.io/),
[CoAP](https://datatracker.ietf.org/doc/html/rfc7252), and socket API.
The socket api supports TCP as well as
[Unix domain sockets](https://man7.org/linux/man-pages/man7/unix.7.html).

The gRPC API uses [protobuf](https://protobuf.dev/) for serialization. The CoAP and socket API
support [JSON](https://datatracker.ietf.org/doc/html/rfc8259) and
[CBOR](https://datatracker.ietf.org/doc/html/rfc8949) for serialization.
The *cmcd* automatically detects the serialization of requests.

The following sections describe the API requests and responses. For protobuf the
[proto3](https://protobuf.dev/programming-guides/proto3/) message syntax is used, for JSON,
[JSON Schema](https://json-schema.org/) is used and for CBOR,
[CDDL](https://datatracker.ietf.org/doc/html/rfc8610) is used.

In the repository, the CoAP and socket API is defined in [api.go](../api/api.go) and the gRPC API
is defined in [grpcapi.proto](../grpcapi/grpcapi.proto).

## API endpoints

This section describes the API endpoints. First, the functionality is described generically, then
for the specific APIs. For generating and verifying attestation reports, only the `Attest` and
`Verify` Endpoints are required.

- `Attest`: Generates an attestation report
- `Verify`: Verifies a provided attestation report
- `TLSSign`: Signs data with a hardware-based key
- `TLSCert`: Returns the certificate chain for a hardware-based key
- `PeerCache`: Returns cached metadata for a peer (see
  [Peer Cache Mechanism](./attestation-protocol.md#peer-cache-mechanism))
- `Measure`: Records a measurement in a hardware trust anchor (such as TPM PCRs)

### gRPC

The CoAP API provides the following services:

- `rpc Attest(AttestationRequest) returns (AttestationResponse)`
- `rpc Verify(VerificationRequest) returns (VerificationResponse)`
- `rpc TLSSign(TLSSignRequest) returns (TLSSignResponse)`
- `rpc TLSCert(TLSCertRequest) returns (TLSCertResponse)`
- `rpc PeerCache(PeerCacheRequest) returns (PeerCacheResponse)`
- `rpc Measure(MeasureRequest) returns (MeasureResponse)`

### CoAP

The CoAP API provides the following endpoints:

- `POST /Attest`
- `POST /Verify`
- `POST /TLSSign`
- `POST /TLSCert`
- `POST /PeerCache`
- `POST /Measure`

### Socket

The socket API uses a simple header followed by a serialized payload:

| Field   | Format            | Description           |
| ------- | ----------------- | --------------------- |
| Length  | 32-bit Big Endian | Length of the payload |
| Type    | 32-bit Big Endian | Type of the payload   |
| Payload | JSON / CBOR       | Serialized payload    |

The following message types are defined:

- `TypeError      = 0`
- `TypeAttest     = 1`
- `TypeVerify     = 2`
- `TypeTLSSign    = 3`
- `TypeTLSCert    = 4`
- `TypePeerCache  = 5`
- `TypeMeasure    = 6`


## Payloads

This section describes the serialized messages / payloads of the API endpoints. Note that the
gRPC APIs only supports protobuf, while the socket and CoAP APIs only support JSON and CBOR.

### Attestation Request

An attestation request instructs the *cmcd* to generate an attestation report with the specified
`nonce`. The `cached` field is an optional list of hex-encoded hash strings of metadata already
present in the requesting party (see
[Peer Cache Mechanism](./attestation-protocol.md#peer-cache-mechanism) for a description of the peer
cache mechanism).

#### JSON
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "nonce": {
      "type": "string",
      "contentEncoding": "base64",
    },
    "cached": {
      "type": "array",
      "items": {
        "type": "string"
      },
      "nullable": true
    }
  },
  "required": ["nonce"],
}
```

#### CBOR
```
AttestationRequest = {
    0: bstr,                          ; Nonce as a byte string
    ? 1: [* tstr]                     ; Optional cached array of text strings
}
```

#### Protobuf
```protobuf
message AttestationRequest {
  bytes nonce = 1;
  repeated string cached = 2;
}
```

### Attestation Response

An attestation response contains the generated attestation `report` and optional `metadata` and an
optional list of `cacheMisses`. `metadata` is a JSON object with metadata items as properties. The
values are the base64-encoded metadata items, the keys are their hex-encoded hash digests.
`cacheMisses` is an array of hexadecimal-encoded hash digests. (see
[Peer Cache Mechanism](./attestation-protocol.md#peer-cache-mechanism) for a description of the
peer cache mechanism).

#### JSON
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "report": {
      "type": "string",
      "contentEncoding": "base64"
    },
    "metadata": {
      "type": "object",
      "additionalProperties": {
        "type": "string",
        "contentEncoding": "base64"
      },
      "nullable": true
    },
    "cacheMisses": {
      "type": "array",
      "items": {
        "type": "string",
        "contentEncoding": "hex"
      },
      "nullable": true
    }
  },
  "required": ["report"]
}
```

#### CBOR
```
AttestationResponse = {
    0: bstr,                          ; Report as a byte string
    ? 1: { tstr => bstr },            ; Metadata as a map of strings to byte strings
    ? 2: [* tstr]                     ; Optional cache misses array of text strings
}
```

#### Protobuf
```protobuf
message AttestationResponse {
  bytes report = 1;
  map<string, bytes> metadata = 2;
  repeated string cache_misses = 3;
}
```

### Verification Request

A verification request provides the required inputs for the *cmcd* to verify an attestation report.
It must contain the base64-encodee `nonce` and `report`, as well as `ca`, which is one or
multiple certificate authorities in PEM format. All other values are optional: `metadata` and
`cacheMisses` have the format as described in the attestation response and can simply be forwarded.
The `peer` is the fingerprint of the peer's TLS certificate required for the peer caching mechanism.
Policies are additional attestation policies to verify against. See
[Peer Cache Mechanism](./attestation-protocol.md#peer-cache-mechanism) and [Policies](./policies.md)
for information on the peer cache mechanism and the policies engine.

#### JSON
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "nonce": {
      "type": "string",
      "contentEncoding": "base64"
    },
    "report": {
      "type": "string",
      "contentEncoding": "base64"
    },
    "metadata": {
      "type": "object",
      "additionalProperties": {
        "type": "string",
        "contentEncoding": "base64",
        "nullable": true
      }
    },
    "ca": {
      "type": "string",
      "contentEncoding": "base64"
    },
    "peer": {
      "type": "string",
      "nullable": true
    },
    "cacheMisses": {
      "type": "array",
      "items": {
        "type": "string"
      },
      "nullable": true
    },
    "policies": {
      "type": "string",
      "contentEncoding": "base64",
      "nullable": true
    }
  },
  "required": ["nonce", "report", "ca"]
}
```

#### CBOR
```
VerificationRequest = {
    0: bstr,                          ; Nonce as a byte string
    1: bstr,                          ; Report as a byte string
    2: { tstr => bstr },              ; Metadata as a map of strings to byte strings
    3: bstr,                          ; CA as a byte string
    ? 4: tstr,                        ; Optional peer string
    ? 5: [* tstr],                    ; Optional cache misses array of text strings
    ? 6: bstr                         ; Optional policies as a byte string
}
```

#### Protobuf
```protobuf
message VerificationRequest {
  bytes nonce = 1;
  bytes report = 2;
  map<string, bytes> metadata = 3;
  bytes ca = 4;
  string peer = 5;
  repeated string cache_misses = 6;
  bytes policies = 7;
}
```

### Verification Response

A verification response contains the `verificationResult` of the verification process.

#### JSON
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "verificationResult": {
      "type": "string",
      "contentEncoding": "base64"
    }
  },
  "required": ["verificationResult"]
}
```

#### CBOR
```
VerificationResponse = {
    0: bstr                           ; Verification result as a byte string
}
```

#### Protobuf
```protobuf
message VerificationResponse {
  bytes verification_result = 1;
}
```

### TLSSign Request

A TLSSign request specifies `content` to be signed with hardware-based keys along with the
hash function `hashType` and optional PSS options `pssOpts`. See [Helper Structs](#helper-structs)
for the type and values of `hashType` and `pssOpts`.

#### JSON
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "content": {
      "type": "string",
      "contentEncoding": "base64"
    },
    "hashType": {
      "type": "string"
    },
    "pssOpts": {
      "type": "object",
      "nullable": true
    }
  },
  "required": ["content", "hashType"]
}
```

#### CBOR
```
TLSSignRequest = {
    0: bstr,                          ; Content as a byte string
    1: tstr,                          ; Hash type as a text string
    ? 2: any                          ; Optional PSS options
}
```

#### Protobuf
```protobuf
message TLSSignRequest {
  bytes content = 1;
  HashFunction hashtype = 2;
  PSSOptions pssOpts = 3;
}
```

### TLSSign Response

A TLSSign response contains the signed content.

#### JSON
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "signedContent": {
      "type": "string",
      "contentEncoding": "base64"
    }
  },
  "required": ["signedContent"]
}
```

#### CBOR
```
TLSSignResponse = {
    0: bstr                           ; Signed content as a byte string
}
```

#### Protobuf
```protobuf
message TLSSignResponse {
  bytes signed_content = 1;
}
```

### TLSCert Request

A TLSCert is a request to retrieve the TLS certificates corresponding to the hardware-based
keys the CMC created. It does not require any properties.

#### JSON
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {}
}
```

#### CBOR
```
TLSCertRequest = {}
```

#### Protobuf
```protobuf
message TLSCertRequest {}
```

### TLSCert Response

A TLSCert response contains a PEM-encoded certificate chain for a hardware-based key.

#### JSON
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "certificate": {
      "type": "array",
      "items": {
        "type": "string",
        "contentEncoding": "base64"
      }
    }
  },
  "required": ["certificate"]
}
```

#### CBOR
```
TLSCertResponse = {
    0: [* bstr]                       ; Certificate chain as an array of byte strings
}
```

#### Protobuf
```protobuf
message TLSCertResponse {
  repeated bytes certificate = 1;
}
```

### PeerCache Request

A PeerCache request retrieves cashed metadata for a peer identified by its TLS certificate
fingerprint `peer` (see [Peer Cache Mechanism](./attestation-protocol.md#peer-cache-mechanism) for a
description of the peer cache mechanism).

#### JSON
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "peer": {
      "type": "string"
    }
  },
  "required": ["peer"]
}
```

#### CBOR
```
PeerCacheRequest = {
    0: tstr                           ; Peer as a text string
}
```

#### Protobuf
```protobuf
message PeerCacheRequest {
  string peer = 1;
}
```

### PeerCache Response

A PeerCache response contains the hash digests of the cached metadata items for a specified peer
(see [Peer Cache Mechanism](./attestation-protocol.md#peer-cache-mechanism) for a description of
the peer cache mechanism).

#### JSON
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "cache": {
      "type": "array",
      "items": {
        "type": "string"
      }
    }
  },
  "required": ["cache"]
}
```

#### CBOR
```
PeerCacheResponse = {
    0: [* tstr]                       ; Cache as an array of text strings
}
```

#### Protobuf
```protobuf
message PeerCacheResponse {
  repeated string cache = 1;
}
```

### Measure Request

A Measure request contains an embedded `measureEvent`. It is used for the user-space container
attestation mechanism to record containers into measurement lists and optionally to hardware
attetation technologies (e.g., into TPM PCRs). This API is used by container runtimes to report
containers they have launched.

#### JSON
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "measureEvent": {
      "type": "object"
    }
  },
  "required": ["measureEvent"]
}
```

#### CBOR
```
MeasureRequest = MeasureEvent
```

#### Protobuf
```protobuf
message MeasureRequest {
  bytes sha256 = 1;
  string event_name = 2;
  CtrData ctr_data = 3;
}
```

### Measure Response

A Measure response indicates whether the CMC measure operation was successful.

#### JSON
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "success": {
      "type": "boolean"
    }
  },
  "required": ["success"]
}
```

#### CBOR
```
MeasureResponse = {
    0: bool                           ; Success as a boolean
}
```

#### Protobuf
```protobuf
message MeasureResponse {
  bool success = 1;
}
```

### Socket Error

A SocketError contains an error message.

#### JSON
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "msg": {
      "type": "string"
    }
  },
  "required": ["msg"]
}
```

#### CBOR
```
SocketError = {
    0: tstr                           ; Message as a text string
}
```


## Helper Structs and Enums

The property `hashType` is an integer with the following value for the hash function:

```
SHA1         = 0
SHA224       = 1
SHA256       = 2
SHA384       = 3
SHA512       = 4
MD4          = 5
MD5          = 6
MD5SHA1      = 7
RIPEMD160    = 8
SHA3_224     = 9
SHA3_256     = 10
SHA3_384     = 11
SHA3_512     = 12
SHA512_224   = 13
SHA512_256   = 14
BLAKE2s_256  = 15
BLAKE2b_256  = 16
BLAKE2b_384  = 17
BLAKE2b_512  = 18
```

## PSSOptions

The `PSSOptions` struct specifies the options for PSS signature schemes, including the salt length.

### JSON
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "saltLength": {
      "type": "integer",
      "description": "The length of the salt used in the PSS signature scheme."
    }
  },
  "required": ["saltLength"]
}
```

### CBOR
```
PSSOptions = {
    0: int                             ; Salt length as an integer
}
```

### Protobuf
```protobuf
message PSSOptions {
  int32 salt_length = 1;
}
```

## MeasureEvent

The `MeasureEvent` struct represents an event to be measured, including a SHA256 hash and optional metadata.

### JSON
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "sha256": {
      "type": "string",
      "contentEncoding": "base64",
      "description": "The SHA256 hash of the event."
    },
    "eventname": {
      "type": "string",
      "nullable": true,
      "description": "The name of the event."
    },
    "eventdata": {
      "type": "object",
      "nullable": true,
      "description": "Additional data related to the event."
    },
    "ctrData": {
      "type": "object",
      "nullable": true,
      "description": "Container-related data associated with the event."
    }
  },
  "required": ["sha256"]
}
```

### CBOR
```
MeasureEvent = {
    2: bstr,                          ; SHA256 hash as a byte string
    ? 4: tstr,                        ; Optional event name as a text string
    ? 5: any,                         ; Optional event data as any type
    ? 6: any                          ; Optional container data as any type
}
```

## CtrData

The `CtrData` struct represents container-related data, including hashes of OCI runtime config and
root filesystem as well the OCI runtime config.

### JSON
```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "properties": {
    "configSha256": {
      "type": "string",
      "contentEncoding": "base64",
      "description": "The SHA256 hash of the container configuration."
    },
    "rootfsSha256": {
      "type": "string",
      "contentEncoding": "base64",
      "description": "The SHA256 hash of the container root filesystem."
    },
    "ociSpec": {
      "type": "object",
      "nullable": true,
      "description": "Optional OCI specification for the container."
    }
  },
  "required": ["configSha256", "rootfsSha256"]
}
```

### CBOR
```
CtrData = {
    0: bstr,                          ; Config SHA256 as a byte string
    1: bstr,                          ; Rootfs SHA256 as a byte string
    ? "ociSpec": any                  ; Optional OCI specification
}
```

### Protobuf
```protobuf
message CtrData {
  bytes configSha256 = 1;
  bytes rootfsSha256 = 2;
  optional bytes ociSpec = 3;
}
```
