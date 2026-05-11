# Run

All binaries can be configured via JSON configuration files and commandline flags. If a
configuration option is specified both via configuration file and commandline flag, the
commandline flag supersedes.

Multiple configuration files can be specified as a comma-separated list. If a specific configuration
option is present in multiple configuration file, the last configuration file takes precedence.

The commandline flags for each executable can be shown via the `--help` flag. The JSON configuration
options have the same names in camel case (e.g. *cmcAddr*), while commandline flags use kebab case
(e.g. *--cmc-addr*).

Furthermore, exemplary JSON configuration file examples can be found in the `examples/` folder of
this repository. Paths in the configuration file can either be absolete or relative to the working
directory.

## cmcctl commands

The cmcctl provides the following subcommands:

- **generate**: Generate attestation report
- **verify**: Verify attestation report
- **enroll-key**: Create and enroll a new TLS key
- **dial**: Establish attested TLS client
- **listen**: Establish attested TLS server
- **request**: Perform an attested HTTPS request
- **serve**: Establish an attested HTTPS server
- **token**: Request a bootstrap token for EST certificate requests
- **provision**: Retrieve provisioning data for CVMs
- **update-certs**: Triggers updating the CMC AK and IK certificates
- **update-metadata**: Triggers updating the CMC metadata
- **proxy**: Forward data over attested TLS using HTTP

## Run the framwork

#### Run the EST and Provisioning Server

```sh
# Start the EST server that supplies the certificates and metadata for the cmcd
estserver --config example-setup/configs/installed/est-server-conf.json
```

#### Run the cmcd

```sh
# Run the cmcd
cmcd --config example-setup/configs/installed/cmcd-conf.json

# NOTE: for setups that require root, e.g., to access the tpm, make sure the installed go binaries
# are found:
sudo env PATH="$HOME/go/bin:$PATH" cmcd --config example-setup/configs/installed/cmcd-conf.json
```

#### Generate and Verify Attestation Reports

```sh
# Run cmcctl to retrieve an attestation report (stored in current folder unless otherwise specified)
cmcctl generate --config example-setup/configs/installed/cmcctl-conf.json

# Run cmcctl to verify the attestation report (stored in current folder unless otherwise specified)
cmcctl verify --config example-setup/configs/installed/cmcctl-conf.json
```

#### Establish Attested TLS Connections

```sh

# Run an attested TLS server
cmcctl listen --config example-setup/configs/installed/cmcctl-conf.json --addr "$(hostname --fqdn):4443"

# Run an attested TLS client estblishing a mutually attested TLS connection to the server
cmcctl dial --config example-setup/configs/installed/cmcctl-conf.json --addr "$(hostname --fqdn):4443"
```

#### Establish Attested HTTPS Connections

```sh
# Run two attested HTTPS servers
cmcctl serve --config example-setup/configs/installed/cmcctl-conf.json --addr "$(hostname --fqdn):8082"

# Perform multiple user-specified attested HTTPS requests to both servers. Each connection is
# attested, while multiple requests to the same server use the established attested TLS connections
cmcctl request \
    --config example-setup/configs/installed/cmcctl-conf.json \
    --addr "https://$(hostname --fqdn):8082" \
    --method POST \
    --data "hello from attested HTTPS client" \
    --header "Content-Type: text/plain"
```

#### Specify custom CA certificates

The below commands show how to build and run the cmcd. At runtime, a client can provide the cmcd
with root certificates that are to be used during the verification of the attestation report. If
these are not provided, the cmcd uses the system's root certificates instead. Under Linux, these are
commonly stored under `/etc/ssl/certs`. To temporarily add certificates, see the commands
using `SSL_CERT_FILE` and `SSL_CERT_DIR` below.

```sh
# Example with added custom certificates
SSL_CERT_FILE=../example-setup/pki/ca/ca.pem ./cmcd --config <config-file>
SSL_CERT_DIR=../example-setup/pki/ca/ ./cmcd --config <config-file>
```

#### Run cmcctl in SGX-Enclave

See [SGX-Setup](./setup-sgx.md).