# Configuration

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
