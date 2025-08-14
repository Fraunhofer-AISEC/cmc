# Developer Documentation

### Integration into Go Projects

The attested TLS or HTTPS libraries can be used within own go projects to provide attestation
for TLS or HTTPS connections, as described in [Integration](./go-integration.md). This is
the easiest way of making using of the CMC attestation framework.

### Integration into Generic Projects

As the *cmcd* provides gRPC, CoAP, and socket APIs, it can be integrated into projects in any
programming language. Attestation reports can be generated and verified using the `generate`
and `verify` endpoint of the *cmcd*. See [APIs and Protocols](#apis-and-protocols).

### APIs and Protocols

For a description of the `cmcd` gRPC, CoaP and socket APIs, refer to [CMCD API](./doc/cmcd-api.md).
These can be used to get certificates and generate and verify attestation reports.

For a description of the attested TLS attestation protocol, refer to
[Attestation Protocol](./attestation-protocol.md). This is an internal protocol, but can serve
as a blueprint for own attested TLS implementations in other programming languages.