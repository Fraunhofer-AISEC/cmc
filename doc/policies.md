# Attestation Policies

The basic attestation report validation verifies all signatures, certificate chains and reference
values against the measurements. To enable custom policies, such as the verification of certain
certificate properties, the blacklisting of certain software artifacts with known vulnerabilities
or the enforcement of a four eyes principle mandating different PKIs for the manifests, the
attestation report module implements a generic policies interface.

## Attestation Result Status

Every result within the attestation result, including the overall `summary`, carries a `status`
field with one of three values:

| Status    | Meaning                                                |
| --------- | ------------------------------------------------------ |
| `success` | The check passed.                                      |
| `warn`    | The check passed, but something non-fatal was detected |
| `fail`    | The check failed.                                      |

The `summary.status` of the attestation result determines whether a peer is accepted: `success` and
`warn` are treated as a successful verification, `fail` is rejected.

## Policy Engines

The `attestationpolicies` module currently implements javascript policy engines. Two engines are
available and can be selected via the `policy-engine` parameter:

| Engine    | Description                                                                         |
| --------- | ----------------------------------------------------------------------------------- |
| `js`      | Pure go [otto](https://github.com/robertkrimen/otto) engine, build tag `jspolicies` |
| `duktape` | C [duktape](https://duktape.org) engine, build tag `duktapepolicies`                |

Arbitrary javascript files can be passed via the `cmcctl` `policies` parameter. The policies
javascript file is then used to evaluate arbitrary attributes of the JSON attestation result
output by the `cmcd` and stored by the `cmcctl`. The attestation result can be referenced via the
`json` variable in the script.

## Return Values

The javascript code can return one of two things:

1. **A boolean**, indicating success or failure of the custom policy validation. The attestation
   result is not modified. If the policy returns `false`, the overall `summary.status` is set to
   `fail` with the error code `VerifyPolicies`.
2. **The modified attestation result**, marshalled via `JSON.stringify()`. In this case, all
   properties of the result, including the `summary.status`, can be overwritten by the policy.
   This must explicitly be enabled via the `policy-overwrite` parameter (`policyOverwrite` in the
   `cmcd` configuration file), otherwise the validation fails. This should be used with care, as
   it allows policies to turn a failed attestation into a successful one.

A minimal policies file, verifying only the `type` field of the attestation result, could look as
follows:

```js
// Parse the result
var obj = JSON.parse(json);
var success = true;

// Check the type field of the result
if (obj.type != "Attestation Result") {
    console.log("Invalid type");
    success = false;
}

success
```

A policy that downgrades a failed attestation result to a warning, so that the connection is still
accepted, must return the modified result and requires `policy-overwrite` to be set:

```js
// Parse the result
var obj = JSON.parse(json);

// Downgrade a failed verification to a warning
if (obj.summary.status == "fail") {
    console.log("Downgrading failed attestation result to warn");
    obj.summary.status = "warn";
}

JSON.stringify(obj)
```

Example policies are provided in [example-setup/policies](../example-setup/policies).
