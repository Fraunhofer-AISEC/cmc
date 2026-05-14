# Manifest Revocation

Throughout the lifetime of a software artifact, security information about a certain software
version and its respective manifest may change, e.g., if new versions of the software become
available, or vulnerabilities in the software are detected.

We support two options for dealing with this situation:
1. **Short-lived manifests**: Manifests can automatically be (re)generated and signed with a short
validity period as long as they are valid.
2. **Online Manifest Status Provider (OMSP) Responses in Attestation Report**: Manifests can include
the URL of an OMSP endpoint that provides the current revocation status of requested manifests as a
signed artefact (OMSP Response). The prover fetches these OMSP Responses on a regular basis and
sends them to the verifier along with other metadata in the attestation report. The mechanism is
comparable to OCSP Stapling for certificate revocation. The communication flows are illustrated in
the following diagram:

![OMSP stapling](./diagrams/OMSP_stapling.drawio.svg)

## OMSP Stapling
In the remainder of this document, we explain how to use the second option.

### Run an OMSP Server
The OMSP server is implemented as part of the provisioning server. Whenever the OMSP endpoint
receives an OMSP Request, it retrieves the current revocation status for the listed manifests,
builds an OMSP Response containing the status information and signs the OMSP Response with a
dedicated OMSP key. Certificates, signature algorithm and signature used for signing the
OMSP response are provided in the standardized JWS or CBOR format.

The OMSP server can be started with:
```sh
estserver -config example-setup/configs/installed/est-server-conf.json
```
It expects the following configuration information in a config file or via commandline:
* omspFolder: A folder with pre-generated JSON files specifying the revocation status for each
manifest named based on the SHA256 hash of the signed manifest (`<hash>.json`).
* omspKey: A private key for signing the OMSP responses.
* omspCaChain: The certificate chain linking the public key belonging to the private `omspKey` to a
trusted CA.
* omspURL: The URL of the OMSP endpoint. This must match the URL referrenced in the manifests
this OMSP server provides a status for.

For the example-setup, OMSP responses can be generated after metadata has been generated and signed,
e.g.,
```sh
generate-metadata-tpm
sign-metadata
generate-omsp-responses
```
The OMSP key and its certificate chain are generated as part of the [setup-pki](../bin/setup-pki) or
[setup-pki-ids](../bin/setup-pki-ids) script.

The revocation status of a manifest can be changed in the respective JSON file in the
[OMSP folder](../data/omsp-raw/). Supported revocation statuses are `good`, `outdated`
(if newer version of the software artifact or its Manifest are available), and `revoked` (if
security issues with the described software are known or relevant security information provided in
the manifest were detected to be false). If the OmspRequest includes manifest hashes that the OMSP
server has no status for, it replies with the status `unknown`.

### Include the URL Endpoint in the manifests
Manifests should define the OMSP endpoint of the running OMSP server.
If a manifest does not contain an URL to an OMSP endpoint, it is currently ignored, i.e., no
revocation information is retrieved on the prover side and no revocation check conducted on the
verifier side.

The generation scripts for the manifests (in `/bin/generate*` and `/bin/precompute*`) include the
optional parameter `--omsp <omsp endpoint>` to set the OMSP endpoint.

### Configure CMC to support manifest revocation
OMSP Stapling can be activated in the CMC via the JSON configuratino file properties:
```json
{
    "useOmsp": true,
    "oscpFormat": "json" // or "cbor"
}
```
or via CLI flags:
```sh
cmcd -config ../example-setup/configs/installed/cmcd-conf.json --use-omsp=true --omsp-format json
```

Acting as a prover, the CMC generates and sends OMSP Requests to all OMSP servers listed in the used
manifests. It stores the received OMSP Responses and transfers them as part of the *metadata* in
the Attestation Report.
OMSP Responses are only valid for a certain time period (currently 7 days) by including a NextUpdate
date in the JSON structure (comparable to OCSP NextUpdate) and the CMC prover fetches new OMSP
responses whenever the stored ones are older than two days.

Acting as a verifier, the CMC validates the signatures of the provided OmspResponses and checks the
revocation status for all utilized manifests. It is currently built to fail remote attestation in
case of issues with parsing/interpreting OMSP information, in case of `revoked` manifests and if
revocation information about a manifest is missing (`unknown`) or oudated (NextUpdate for
manifest has passed). In case manifests themselves are marked as `outdated` (signaling that newer
versions of the software or the manifest are available, but without security-critical issues about
the current version), the remote attestation success status is set to `warn`.