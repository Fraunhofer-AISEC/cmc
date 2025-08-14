# Attestation Policies

The basic attestation report validation verifies all signatures, certificate chains and reference
values against the measurements. To enable custom policies, such as the verification of certain
certificate properties, the blacklisting of certain software artifacts with known vulnerabilities
or the enforcement of a four eyes principle mandating different PKIs for the manifests, the
attestation report module implements a generic policies interface.

The current implementation contains the `attestationpolicies` module which implements a javascript
engine. This allows passing arbitrary javascript files via the `cmcctl` `-policies` parameter.
The policies javascript file is then used to evaluate arbitrary attributes of the JSON
attestation result output by the `cmcd` and stored by the `cmcctl`. The attestation result
can be referenced via the `json` variable in the script. The javascript code must return a single
boolean indicating success or failure of the custom policy validation. A minimal policies file,
verifying only the `type` field of the attesation result could look as follows:

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

Via the `overwritePolicies` configuration parameter, fields of the verification result can even
be overwritten, e.g. from `fail` to `warn` to allow less strict checking. This should be used
with care.
