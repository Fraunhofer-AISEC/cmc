# CMC API

This document describes the *cmcd* APIs. For documentation, where this API is used, refer to
[Architecture](./architecture.md). The *cmcd* provides a [gRPC](https://grpc.io/) and a socket API.
The socket api supports TCP as well as
[Unix domain sockets](https://man7.org/linux/man-pages/man7/unix.7.html).

The gRPC API uses [protobuf](https://protobuf.dev/) for serialization. The socket API supports
[JSON](https://datatracker.ietf.org/doc/html/rfc8259) and
[CBOR](https://datatracker.ietf.org/doc/html/rfc8949) for serialization. The *cmcd* automatically
detects the serialization of requests.

The following sections describe the API requests and responses. For protobuf the
[proto3](https://protobuf.dev/programming-guides/proto3/) message syntax is used, for JSON,
[JSON Schema](https://json-schema.org/) is used and for CBOR,
[CDDL](https://datatracker.ietf.org/doc/html/rfc8610) is used.

In the repository, the socket API is defined in [api.go](../api/api.go) and the gRPC API
is defined in [grpcapi.proto](../grpcapi/grpcapi.proto).

## API endpoints

This section describes the API endpoints. First, the functionality is described generically, then
for the specific APIs. For generating and verifying attestation reports, only the `Attest` and
`Verify` Endpoints are required.

- `Attest`: Generates an attestation report
- `Verify`: Verifies a provided attestation report
- `TLSCreate`: Creates a hardware-based key and enrolls a certificate for it
- `TLSSign`: Signs data with a hardware-based key
- `TLSCert`: Returns the certificate chain for a hardware-based key
- `PeerCache`: Returns cached metadata for a peer (see
  [Peer Cache Mechanism](./attestation-protocol.md#peer-cache-mechanism))
- `Measure`: Records a measurement in a hardware trust anchor (such as TPM PCRs)
- `UpdateCerts`: Renews the certificates of the attestation drivers
- `UpdateMetadata`: Reloads the metadata from the configured locations

### gRPC

The gRPC API provides the following services:

- `rpc Attest(AttestationRequest) returns (AttestationResponse)`
- `rpc Verify(VerificationRequest) returns (VerificationResponse)`
- `rpc TLSCreate(TLSCreateRequest) returns (TLSCreateResponse)`
- `rpc TLSSign(TLSSignRequest) returns (TLSSignResponse)`
- `rpc TLSCert(TLSCertRequest) returns (TLSCertResponse)`
- `rpc PeerCache(PeerCacheRequest) returns (PeerCacheResponse)`
- `rpc Measure(MeasureRequest) returns (MeasureResponse)`
- `rpc UpdateCerts(UpdateCertsRequest) returns (UpdateCertsResponse)`
- `rpc UpdateMetadata(UpdateMetadataRequest) returns (UpdateMetadataResponse)`

### Socket

The socket API uses a simple header followed by a serialized payload:

| Field   | Format            | Description           |
| ------- | ----------------- | --------------------- |
| Length  | 32-bit Big Endian | Length of the payload |
| Type    | 32-bit Big Endian | Type of the payload   |
| Payload | JSON / CBOR       | Serialized payload    |

Requests and responses use the same type. The message types are defined in [api.go](../api/api.go).
If a request fails, the *cmcd* responds with a `SocketError` of type `TypeError`. The following
message types are defined:

- `TypeError`
- `TypeAttest`
- `TypeVerify`
- `TypeTLSCreate`
- `TypeTLSSign`
- `TypeTLSCert`
- `TypePeerCache`
- `TypeMeasure`
- `TypeUpdateCerts`
- `TypeUpdateMetadata`

## Payloads

This section describes the serialized messages / payloads of the API endpoints. Note that the
gRPC APIs only supports protobuf, while the socket API only supports JSON and CBOR.

All JSON schema definitions can be found [here](./api/json/). For each message, the link
to the JSON schema definition is provided in the following sections. CBOR and protobuf definitions
are directly embedded into the document. Byte strings are base64-encoded in JSON.

### Attestation Request

An attestation request instructs the *cmcd* to generate an attestation report with the specified
`nonce`. The `cached` field is an optional list of hex-encoded hash strings of metadata already
present in the requesting party (see
[Peer Cache Mechanism](./attestation-protocol.md#peer-cache-mechanism) for a description of the peer
cache mechanism). The optional `claims` are prover-asserted key/value pairs that are placed into the
report context.

#### JSON
See [AttestationRequest](./api/json/api/AttestationRequest.json)

#### CBOR
```
AttestationRequest = {
  0: tstr,                          ; Version - protocol version
  1: bstr,                          ; Nonce as a byte string
  ? 2: [* tstr],                    ; Optional cached metadata digests as hex strings
  ? 3: { tstr => bstr }             ; Optional claims as a map of strings to byte strings
}
```

#### Protobuf
```protobuf
message AttestationRequest {
  string version = 1;
  bytes nonce = 2;
  repeated string cached = 3;
  map<string, bytes> claims = 4;
}
```

### Attestation Response

An attestation response contains the generated attestation `report`. The report embeds the
metadata that is not present in the requesting party's cache.

#### JSON
See [AttestationResponse](./api/json/api/AttestationResponse.json)

#### CBOR
```
AttestationResponse = {
  0: tstr,                          ; Version - protocol version
  1: bstr                           ; Report as a byte string
}
```

#### Protobuf
```protobuf
message AttestationResponse {
  string version = 1;
  bytes report = 2;
}
```

### Verification Request

A verification request provides the required inputs for the *cmcd* to verify an attestation report.
It must contain the `nonce` and the `report`. All other values are optional. The `peer` is the
fingerprint of the peer's TLS certificate required for the peer caching mechanism, `peerAddr` is
the network address of the peer and `policies` are additional attestation policies to verify
against. See [Peer Cache Mechanism](./attestation-protocol.md#peer-cache-mechanism) and
[Policies](./policies.md) for information on the peer cache mechanism and the policies engine.

#### JSON
See [VerificationRequest](./api/json/api/VerificationRequest.json)

#### CBOR
```
VerificationRequest = {
  0: tstr,                          ; Version - protocol version
  1: bstr,                          ; Nonce as a byte string
  2: bstr,                          ; Report as a byte string
  ? 6: tstr,                        ; Optional peer TLS certificate fingerprint
  ? 7: tstr,                        ; Optional peer network address
  ? 8: bstr                         ; Optional policies as a byte string
}
```

#### Protobuf
```protobuf
message VerificationRequest {
  string version = 1;
  bytes nonce = 2;
  bytes report = 3;
  string peer = 7;
  string peer_addr = 8;
  bytes policies = 9;
}
```

### Verification Response

A verification response contains the attestation result of the verification process. In protobuf,
the result is serialized as JSON.

#### JSON
See [VerificationResponse](./api/json/api/VerificationResponse.json)

#### CBOR
```
VerificationResponse = {
  0: tstr,                          ; Version - protocol version
  1: any                            ; Attestation result
}
```

#### Protobuf
```protobuf
message VerificationResponse {
  string version = 1;
  bytes result = 2;
}
```

### TLSCreate Request

A TLSCreate request instructs the *cmcd* to create a new key and to enroll a certificate for it.
The `keyConfig` specifies the key `type` (`tpm`, `sw` or `snp`), the key algorithm `alg` (`ec256`,
`ec384`, `ec521`, `rsa2048` or `rsa4096`), the subject common name `cn` and optional DNS and IP
subject alternative names.

#### JSON
See [TLSCreateRequest](./api/json/api/TLSCreateRequest.json)

#### CBOR
```
TLSCreateRequest = {
  0: tstr,                          ; Version - protocol version
  1: TLSKeyConfig                   ; Key configuration
}

TLSKeyConfig = {
  1: tstr,                          ; Key type
  2: tstr,                          ; Key algorithm
  3: tstr,                          ; Subject common name
  ? 4: [* tstr],                    ; Optional DNS names
  ? 5: [* tstr]                     ; Optional IP addresses
}
```

#### Protobuf
```protobuf
message TLSCreateRequest {
  string version = 1;
  TLSKeyConfig key_config = 2;
}

message TLSKeyConfig {
  string type = 1;
  string alg = 2;
  string cn = 3;
  repeated string dns_names = 4;
  repeated string ip_addresses = 5;
}
```

### TLSCreate Response

A TLSCreate response contains the ID of the created key, which is used to reference the key in
subsequent TLSSign and TLSCert requests.

#### JSON
See [TLSCreateResponse](./api/json/api/TLSCreateResponse.json)

#### CBOR
```
TLSCreateResponse = {
  0: tstr,                          ; Version - protocol version
  1: tstr                           ; Key ID
}
```

#### Protobuf
```protobuf
message TLSCreateResponse {
  string version = 1;
  string key_id = 2;
}
```

### TLSSign Request

A TLSSign request specifies the `content` to be signed with the key identified by `keyId`. The
content is the digest computed with the hash algorithm `hashAlg` (`SHA-256`, `SHA-384` or
`SHA-512`).

#### JSON
See [TLSSignRequest](./api/json/api/TLSSignRequest.json)

#### CBOR
```
TLSSignRequest = {
  0: tstr,                          ; Version - protocol version
  1: tstr,                          ; Key ID
  2: bstr,                          ; Content (digest) as a byte string
  3: tstr                           ; Hash algorithm
}
```

#### Protobuf
```protobuf
message TLSSignRequest {
  string version = 1;
  string key_id = 2;
  bytes content = 3;
  string hash_alg = 4;
}
```

### TLSSign Response

A TLSSign response contains the signature.

#### JSON
See [TLSSignResponse](./api/json/api/TLSSignResponse.json)

#### CBOR
```
TLSSignResponse = {
  0: tstr,                          ; Version - protocol version
  1: bstr                           ; Signature as a byte string
}
```

#### Protobuf
```protobuf
message TLSSignResponse {
  string version = 1;
  bytes signed_content = 2;
}
```

### TLSCert Request

A TLSCert request retrieves the certificate chain of the key identified by `keyId`.

#### JSON
See [TLSCertRequest](./api/json/api/TLSCertRequest.json)

#### CBOR
```
TLSCertRequest = {
  0: tstr,                          ; Version - protocol version
  1: tstr                           ; Key ID
}
```

#### Protobuf
```protobuf
message TLSCertRequest {
  string version = 1;
  string key_id = 2;
}
```

### TLSCert Response

A TLSCert response contains the PEM-encoded certificate chain of the key.

#### JSON
See [TLSCertResponse](./api/json/api/TLSCertResponse.json)

#### CBOR
```
TLSCertResponse = {
  0: tstr,                          ; Version - protocol version
  1: [* bstr]                       ; Certificate chain as an array of byte strings
}
```

#### Protobuf
```protobuf
message TLSCertResponse {
  string version = 1;
  repeated bytes certificate = 2; // PEM encoded
}
```

### PeerCache Request

A PeerCache request retrieves cached metadata for a peer identified by its TLS certificate
fingerprint `peer` (see [Peer Cache Mechanism](./attestation-protocol.md#peer-cache-mechanism) for a
description of the peer cache mechanism).

#### JSON
See [PeerCacheRequest](./api/json/api/PeerCacheRequest.json)

#### CBOR
```
PeerCacheRequest = {
  0: tstr,                          ; Version - protocol version
  1: tstr                           ; Peer as a text string
}
```

#### Protobuf
```protobuf
message PeerCacheRequest {
  string version = 1;
  string peer = 2;
}
```

### PeerCache Response

A PeerCache response contains the hash digests of the cached metadata items for a specified peer
(see [Peer Cache Mechanism](./attestation-protocol.md#peer-cache-mechanism) for a description of
the peer cache mechanism).

#### JSON
See [PeerCacheResponse](./api/json/api/PeerCacheResponse.json)

#### CBOR
```
PeerCacheResponse = {
  0: tstr,                          ; Version - protocol version
  1: [* tstr]                       ; Cache as an array of text strings
}
```

#### Protobuf
```protobuf
message PeerCacheResponse {
  string version = 1;
  repeated string cache = 2;
}
```

### Measure Request

A Measure request contains the measured `event` as a [Component](#component). It is used for the
user-space container attestation mechanism to record containers into measurement lists and
optionally into hardware attestation technologies (e.g., into TPM PCRs). This API is used by
container runtimes to report containers they have launched.

#### JSON
See [MeasureRequest](./api/json/api/MeasureRequest.json)

#### CBOR
```
MeasureRequest = {
  0: tstr,                          ; Version - protocol version
  1: Component                      ; Measured event
}
```

#### Protobuf
```protobuf
message MeasureRequest {
  string version = 1;
  Component measure_event = 2;
}
```

### Measure Response

A Measure response indicates whether the CMC measure operation was successful.

#### JSON
See [MeasureResponse](./api/json/api/MeasureResponse.json)

#### CBOR
```
MeasureResponse = {
  0: tstr,                          ; Version - protocol version
  1: bool                           ; Success as a boolean
}
```

#### Protobuf
```protobuf
message MeasureResponse {
  string version = 1;
  bool success = 2;
}
```

### UpdateCerts Request

An UpdateCerts request instructs the *cmcd* to renew the certificates of all attestation drivers.
It does not have any further properties.

#### JSON
See [UpdateCertsRequest](./api/json/api/UpdateCertsRequest.json)

#### CBOR
```
UpdateCertsRequest = {
  0: tstr                           ; Version - protocol version
}
```

#### Protobuf
```protobuf
message UpdateCertsRequest {
  string version = 1;
}
```

### UpdateCerts Response

An UpdateCerts response indicates whether the certificates were renewed successfully.

#### JSON
See [UpdateCertsResponse](./api/json/api/UpdateCertsResponse.json)

#### CBOR
```
UpdateCertsResponse = {
  0: tstr,                          ; Version - protocol version
  1: bool                           ; Success as a boolean
}
```

#### Protobuf
```protobuf
message UpdateCertsResponse {
  string version = 1;
  bool success = 2;
}
```

### UpdateMetadata Request

An UpdateMetadata request instructs the *cmcd* to reload the metadata from the configured
locations. It does not have any further properties.

#### JSON
See [UpdateMetadataRequest](./api/json/api/UpdateMetadataRequest.json)

#### CBOR
```
UpdateMetadataRequest = {
  0: tstr                           ; Version - protocol version
}
```

#### Protobuf
```protobuf
message UpdateMetadataRequest {
  string version = 1;
}
```

### UpdateMetadata Response

An UpdateMetadata response indicates whether the metadata was reloaded successfully.

#### JSON
See [UpdateMetadataResponse](./api/json/api/UpdateMetadataResponse.json)

#### CBOR
```
UpdateMetadataResponse = {
  0: tstr,                          ; Version - protocol version
  1: bool                           ; Success as a boolean
}
```

#### Protobuf
```protobuf
message UpdateMetadataResponse {
  string version = 1;
  bool success = 2;
}
```

### Socket Error

A SocketError contains an error message.

#### JSON
See [SocketError](./api/json/api/SocketError.json)

#### CBOR
```
SocketError = {
  0: tstr,                          ; Version - protocol version
  1: tstr                           ; Message as a text string
}
```

## Component

The `Component` struct describes a measured software component. For the Measure request, the
relevant properties are the `type`, the `name`, the `hashes` of the event, the target index (e.g.,
the TPM PCR) as property `cmc.index` and the container data `ctrData`. The full definition including
all optional properties can be found in [Component](./api/json/attestationreport/Component.json).

### CBOR
```
Component = {
  0: tstr,                          ; Type
  1: tstr,                          ; Name
  ? 2: [* ReferenceHash],           ; Optional hashes, one per hash algorithm
  ? 6: [* Property],                ; Optional properties, e.g. cmc.index
  ? 8: CtrData,                     ; Optional container data
  * int => any                      ; Further optional properties, see the JSON schema
}

ReferenceHash = {
  0: tstr,                          ; Hash algorithm, e.g. SHA-256
  1: bstr                           ; Digest
}

Property = {
  0: tstr,                          ; Name
  1: tstr                           ; Value
}
```

### Protobuf
```protobuf
message Component {
  string type = 1;
  string name = 2;
  int32 index = 3;
  repeated Hash hashes = 4;
  string version = 5;
  bool optional = 6;
  string description = 7;
  CtrData ctr_data = 9;
}

message Hash {
  string alg = 1;
  bytes Content = 2;
}
```

## CtrData

The `CtrData` struct represents container-related data, including hashes of OCI runtime config and
root filesystem as well the OCI runtime config.

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
  bytes config_sha256 = 1;
  bytes rootfs_sha256 = 2;
  bytes oci_spec = 3;
}
```
