# caddy-atls

A Caddy plugin that wraps a TLS listener with attested TLS (aTLS) using the
[Fraunhofer AISEC CMC](https://github.com/Fraunhofer-AISEC/cmc) library. The
plugin registers as the Caddy module `caddy.listeners.atls`.

## Build

The plugin is compiled into a custom Caddy binary via
[`xcaddy`](https://github.com/caddyserver/xcaddy):

```bash
CGO_ENABLED=1 go tool xcaddy build --with github.com/Fraunhofer-AISEC/cmc/tools/atlscaddy \
    --replace github.com/Fraunhofer-AISEC/cmc=.
```

`CGO_ENABLED=1` can be omitted if the cmc is built without SGX support

## Example setups

The plugin ships with example configs:

### Hello World

[hello-world.caddyfile](../../example-setup/configs/hello-world.caddyfile) provides a minimal end-to-end check.
Caddy terminates aTLS on `https://localhost:4445` and simply responds with `"Hello, World"`.

### Reverse Proxy

[reverse-proxy.caddyfile](../../example-setup/configs/reverse-proxy.caddyfile) lets
Caddy acts as an aTLS front-end for a legacy HTTP service that does not
itself support attestation. Requests to `https://localhost:4445` complete an
attested handshake, then Caddy reverse-proxies plain HTTP to a backend on
`127.0.0.1:8080`. This lets you operate your own plain HTTP server on `127.0.0.1:8080`.

### Hello World Reverse Proxy

[hello-world-reverse-proxy.caddyfile](../../example-setup/configs/hello-world-reverse-proxy.caddyfile) extends
the [reverse-proxy.caddyfile](../../example-setup/configs/reverse-proxy.caddyfile), through additionally
configuring an example legacy hello world backend as a second site which simply responds with
`"Hello World from Legacy HTTP Server"` for and end-to-end test.

### Hello World Reverse Proxy + mTLS

[hello-world-reverse-proxy-mtls.caddyfile](../../example-setup/configs/hello-world-reverse-proxy-mtls.caddyfile)
extends [hello-world-reverse-proxy.caddyfile](../../example-setup/configs/hello-world-reverse-proxy.caddyfile)
with `attest mutual` at the aTLS layer and client-certificate authentication (mTLS) at the TLS
layer.

## Run

Run `caddy-atls` like this:
```sh
./caddy run --config <path/to/caddyfile>
```

## Full Example

For a full example with a legacy client and legacy server connecting via aTLS through
client-side `cmcctl proxy` and server-side `caddy-atls` reverse proxy refer to the
[proxy documentation](../../doc/run.md#run-legacy-http-client-and-server-via-atls-proxies).

## Configuration Reference

The `atls` block accepts the following options (all optional):

| Option        | Values                               | Notes                            |
| ------------- | ------------------------------------ | -------------------------------- |
| `cmc_api`     | `socket`, `grpc`, `coap`             | API used to reach the CMC daemon |
| `cmc_addr`    | `host:port`                          | CMC daemon address               |
| `attest`      | `mutual`, `client`, `server`, `none` | Which side is required to attest |
| `serializer`  | `json`, `cbor`                       | Attestation report encoding      |
| `policy_file` | `path`                               | Path to a CMC policy file        |

The `atls` wrapper must appear **first** in `listener_wrappers` because it
wraps the raw TLS listener.
