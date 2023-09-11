# Configuration

All binaries can be configured via JSON configuration files and commandline flags. If a
configuration option is specified both via configuration file and commandline flag, the
commandline flag supersedes.

The commandline flags can be shown via `<binary> -help`. Exemplary JSON configuration file examples
can be found in the `examples/` folder of this repository. Paths in the configuration file can
either be absolete or relative to the working directory.

The remainder of this section explains the different options.

## CMCD Configuration

- **addr**: The address the *cmcd* should listen on, e.g. 127.0.0.1:9955
- **provServerAddr**: The URL of the provisioning server. The server issues certificates for the
TPM or software keys. In case of the TPM, the TPM *Credential Activation* process is performed.
- **metadata**: A list of locations to fetch metadata from. This can be local files, e.g.,
`file://manifest.json`, local folders, e.g., `file:///var/metadata/`, or remote HTTPS URLs,
e.g., `https://localhost:9000/metadata`
- **drivers**: Tells the *cmcd* prover which drivers to use, currently
supported are `TPM`, `SNP`, and `SW`. If multiple drivers are used for measurements, always the
first provided driver is used for signing operations
- **useIma**: Bool that indicates whether the Integrity Measurement Architecture (IMA) shall be used
- **imaPcr**: TPM PCR where the IMA measurements are recorded (must match the kernel
configuration). The linux kernel default is 10
- **keyConfig**: The algorithm to be used for the *cmcd* keys. Possible values are:  RSA2048,
RSA4096, EC256, EC384, EC521
- **serialization**: The serialiazation format to use for the attestation report. Can be either
`cbor` or `json`
- **api**: Selects whether to use the `grpc`, `coap`, or `socket` API
- **network**: Only relevant for the `socket` API, selects whether to use `TCP` or
`Unix Domain Sockets`
- **logLevel**: The logging level. Possible are trace, debug, info, warn, and error.
- **cache** : An optional folder the *cmcd* uses to cache retrieved metadata. If one or multiple
locations specified via **metadata** cannot be fetched, the *cmcd** additionally uses this cache.
File are stored by their sha256 hash as a filename and in case of duplicates, always the newest
version of a metadata item is chosen
- **storage**: An optional local storage path. If provided, the *cmcd* uses this path to store
internal data such as downloaded certificates or created key handles

## EST Server Configuration

- **port**: The port the server should listen on
- **signingKey**: The private key of the CA used to sign the device certificates.
- **signingCerts**: The certificate chain of the CA used to sign the device certificates.
- **httpFolder**: The root folder containing metadata (manifests and descriptions) that is served
by the provisioning server to be fetched by the `cmcd`
- **verifyEkCert**: Boolean, specifies if the EK certificate chain should be validated via the
**tpmEkCertDb**
- **tpmEkCertDb**: SQLite database containing intermediate CA and CA certificates from the TPM
manufacturers. The provisioning server uses these certificates to verify the TPM
Endorsement Key (EK) certificate. The repository contains an example database with the
certificates of some TPM manufacturers which can be used. For different manufacturers,
certificates might need to be added.
- **vcekOfflineCaching**: Boolean, specifies whether AMD SEV-SNP VCEK certificates downloaded from
the AMD KDS server should be stored locally for later offline retrieval
- **vcekCacheFolder**: The folder the downloaded VCEK certificates should locally be stored (only
relevant if vcekOfflineCaching is set to true)
- **estKey**: Server private key for establishing HTTPS connections
- **estCerts**: Server certificate chain(s) for establishing HTTPS connections
- **logLevel**: The logging level. Possible are trace, debug, info, warn, and error.

## Testtool Configuration

- **mode**: The mode to run. Possible are generate, verify, dial, listen, cacerts and iothub
- **addr**: List of addresses to connect to in mode dial and anddress to serve in mode listen.
- **cmc**: The address of the CMC server
- **report**: The file to store the attestation report in (mode generate) or to retrieve
from (mode verify)
- **result**: The file to store the attestation result in (mode verify)
- **nonce**: The file to store the nonce in (mode generate) or to retrieve from (mode verify)
- **ca**: The trust anchor CA(s)
- **policies**: Optional policies files
- **mtls**: Perform mutual TLS in mode dial and listen
- **api**: Selects whether to use the `grpc`, `coap`, or `socket` API
- **network**: Only relevant for the `socket` API, selects whether to use `TCP` or
`Unix Domain Sockets`
- **logLevel**: The logging level. Possible are trace, debug, info, warn, and error.
- **interval**: Interval at which dial will be executed. If set to `0s` or less, then dial will only execute once.
The interval format has to be in accordance with the input format of Go's
[`time.Duration`](https://pkg.go.dev/time#ParseDuration).

**The testtool can run the following commands/modes:**
- **cacerts**: Retrieves the CA certificates from the EST server
- **generate**: Generates an attestation report and stores it under the specified path
- **verify**: Verifies a previously generated attestation report
- **dial**: Run attestedTLS client application
- **listen**: Serve as a attestedTLS echo server

## Platform Configuration

The *cmcd* does not provide platform security itself, it only allows to make verifiable claims
about the software running on a platform. Thus, a secure base plaftorm is essential for the
overall security of the platform. This includes the kernel configuration, OS configuration,
file systems and software running on the host. Some configurations are mandatory for the *cmcd*
to work (e.g., if used, TPM-support must be enabled in the kernel configuration).

Further information about the platform configuration can be found
[here](doc/platform-configuration.md)

## Custom Policies

The basic validation verifies all signatures, certificate chains and reference values against the
measurements. To enable custom policies, such as the verification of certain certificate properties,
the blacklisting of certain software artifacts with known vulnerabilities or the enforcement of a
four eyes principle mandating different PKIs for the manifests, the attestation report module
implements a generic policies interface.

The current implementation contains the `attestationpolicies` module which implements a javascript
engine. This allows passing arbitrary javascript files via the `testtool` `-policies` parameter.
The policies javascript file is then used to evaluate arbitrary attributes of the JSON
attestation result output by the `cmcd` and stored by the `testtool`. The attestation result
can be referenced via the `json` variable in the script. The javascript code must return a single
boolean indicating success or failure of the custom policy validation. A minimal policies file, verifying only the `type` field of the attesation result could look as follows:

```js
// Parse the verification result
var obj = JSON.parse(json);
var success = true;

// Check the type field of the verification result
if (obj.type != "Verification Result") {
    console.log("Invalid type");
    success = false;
}

success
```