# SPIRE Plugins

External [SPIRE](https://github.com/spiffe/spire) plugins that issue SPIFFE identities only to
nodes whose integrity has been proven by CMC remote attestation.

| Binary                    | Plugin                        |
| ------------------------- | ----------------------------- |
| `spire-agent-plugin-cmc`  | `NodeAttestor "cmc"` (agent)  |
| `spire-server-plugin-cmc` | `NodeAttestor "cmc"` (server) |

Build and install:

```sh
make build-spire
sudo make install-spire
```

## Node Attestor

Challenge-response attestation with CMC as verifier and the server plugin as relying party:

1. The agent plugin sends its protocol version.
2. The server plugin replies with a fresh nonce.
3. The agent plugin requests an attestation report for this nonce from the local `cmcd` via gRPC
   and returns it. The report carries the node ID as claim `spire.cmc.node-id`.
4. The server plugin verifies the report with the embedded CMC verifier against its root CAs and
   optional policies. Any summary other than `success` rejects the attestation.

The node ID is a UUID that the agent plugin creates once and persists in `node_id_path`. As claim,
it is part of the hashed report context and thus bound to the hardware evidence. The agent ID is
`spiffe://<trust-domain>/spire/agent/cmc/<node-id>`.

The plugin supports re-attestation, so every agent SVID renewal re-runs the full attestation.
The report is not bound to the agent SVID key.

### Selectors

| Selector                                 | Source                                                          |
| ---------------------------------------- | --------------------------------------------------------------- |
| `cmc:attest-level:hardware` / `software` | `AttestLevel` of the attestation result                         |
| `cmc:tech:<type>`                        | One per measurement result type, e.g. `tpm`, `snp`, `tdx`, `sw` |

Azure CVMs yield `tech:snp` or `tech:tdx` plus `tech:tpm`.

### Configuration

Agent (`cmcd` must serve the gRPC API, e.g. `--cmc grpc://127.0.0.1:9955`):

```conf
NodeAttestor "cmc" {
    plugin_cmd = "/usr/local/bin/spire-agent-plugin-cmc"
    plugin_data {
        node_id_path = "/var/lib/spire/agent/cmc-node-id"
        cmc_addr     = "localhost:9955"    # optional, default localhost:9955, or a unix socket path
    }
}
```

Server:

```conf
NodeAttestor "cmc" {
    plugin_cmd = "/usr/local/bin/spire-server-plugin-cmc"
    plugin_data {
        root_cas      = ["/etc/spire/cmc/ca.pem"]
        policies      = "/etc/spire/cmc/policy.js"    # optional
        policy_engine = "js"                          # optional, default js
    }
}
```
