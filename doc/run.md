# Run

All binaries can be configured via JSON configuration files and commandline flags. If a
configuration option is specified both via configuration file and commandline flag, the
commandline flag supersedes.

Multiple configuration files can be specified as a comma-separated list. If a specific configuration
option is present in multiple configuration file, the last configuration file takes precedence.

The commandline flags for each executable can be shown via the `-help` flag. The JSON configuration
options have the same names, except that commandline flags are all lower case (e.g. *cmcaddr*),
while JSON properties are camel case (e.g. *cmcAddr*).

Furthermore, exemplary JSON configuration file examples can be found in the `examples/` folder of
this repository. Paths in the configuration file can either be absolete or relative to the working
directory.

## Testtool modes

The testtool can run the following commands/modes, specified via the `-mode` flag or the
`mode` JSON configuration file property:

- **cacerts**: Retrieves the CA certificates from the EST server
- **generate**: Generates an attestation report and stores it under the specified path
- **verify**: Verifies a previously generated attestation report
- **dial**: Run attestedTLS client application
- **listen**: Serve as a attestedTLS echo server
- **request**: Performs one or multiple attested HTTPS requests (client)
- **serve**: Run attested HTTPS demo server

## Run the framwork

#### Run the EST and Provisioning Server

```sh
# Start the EST server that supplies the certificates and metadata for the cmcd
./estserver -config cmc-data/est-server-conf.json
```

#### Run the cmcd

```sh
# Build and run the cmcd
./cmcd -config cmc-data/cmcd-conf.json
```

#### Generate and Verify Attestation Reports

```sh
# Run the testtool to retrieve an attestation report (stored in current folder unless otherwise specified)
./testtool -mode generate

# Run the testtool to verify the attestation report (stored in current folder unless otherwise specified)
./testtool -mode verify -ca cmc-data/pki/ca.pem
```

#### Establish Attested TLS Connections

```sh

# Run an attested TLS server
./testtool -mode listen -addr 0.0.0.0:4443 -ca cmc-data/pki/ca.pem -mtls

# Run an attested TLS client estblishing a mutually attested TLS connection to the server
./testtool -mode dial -addr localhost:4443 -ca cmc-data/pki/ca.pem -mtls
```

#### Establish Attested HTTPS Connections

```sh
# Run two attested HTTPS servers
./testtool -config testtool-config.json -addr 0.0.0.0:8081 -mode serve

# Perform multiple user-specified attested HTTPS requests to both servers. Each connection is
# attested, while multiple requests to the same server use the established attested TLS connections
./testtool \
    -config ../data/testtool-config.json \
    -addr https://localhost:8081/post,https://localhost:8082/post \
    -mode request \
    -method POST \
    -data "hello from attested HTTPS client" \
    -header "Content-Type: text/plain"
```

#### Specify custom CA certificates

The below commands show how to build and run the cmcd. At runtime, a client can provide the cmcd
with root certificates that are to be used during the verification of the attestation report. If
these are not provided, the cmcd uses the system's root certificates instead. Under Linux, these are
commonly stored under `/etc/ssl/certs`. To temporarily add certificates, see the commands
using `SSL_CERT_FILE` and `SSL_CERT_DIR` below.

```sh
# Example with added custom certificates
SSL_CERT_FILE=../example-setup/pki/ca/ca.pem ./cmcd -config <config-file>
SSL_CERT_DIR=../example-setup/pki/ca/ ./cmcd -config <config-file>
```

#### Run testtool in SGX-Enclave

See [SGX-Setup](./setup-sgx.md).