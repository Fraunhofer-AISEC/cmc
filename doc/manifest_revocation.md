# Manifest Revocation

Throughout the lifetime of a software artifact, security information about a certain software version and, therefore, its respective manifest may change, e.g., if new versions of the software become available, vulnerabilities in the software are detected, or errors in the signed metadata are found.
The remote attestation should only be successful if the utilized software is still trusted at the time of the validation.

We support two options for dealing with this situation:
1. **Short-lived manifests**: Manifests can automatically be (re)generated and signed with a short validity period as long as they are valid.
2. **Online Manifest Status Provider (OMSP) Responses in Attestation Report**: Manifests can include the URL of an OMSP endpoint that provides the current revocation status of requested manifests as a signed artefact (OMSP Response). The prover fetches these OMSP Responses on a regular basis and sends them to the verifier along with other metadata in the attestation report. The mechanism is comparable to OCSP Stapling for certificate revocation. The communication flows are illustrated in the following diagram:
![OMSP stapling](./diagrams/OMSP_stapling.drawio.svg)

## OMSP Stapling
In the following, we explain how to use the second option with our framework:

### Run an OMSP Server
The OMSP server is implemented as part of the provisioning server. Whenever the OMSP endpoint receives an OMSP Request, it retreives the current revocation status for the listed SW manifests, builds an OMSP Response containing all this status information and signs the OMSP Response with a dedicated private OMSP key. Certificates, SignatureAlgorithm and Signature used for signing the OmspResponse are provided in the standardized JWS or CBOR format.

The OMSP server can be started with:
```sh
cmc-docker vm-estserver
```
It expects the following configuration information in a config file or via commandline:
* omspFolder: A folder with pre-generated JSON files specifying the revocation status for each SW manifest named based on the SHA256 hash of the signed SW manifest (<hash>.json).
* omspKey: A private key for signing the OMSP responses.
* omspCaChain: The certificate chain linking the public key belonging to the private omspKey to a trusted CA.
* omspURL: The URL of the OMSP endpoint. This must match the URL referrenced in the SW manifests this OMSP server provides a status for.

For the example-setup, an omspFolder listing all SW manifests as "valid"  can be generated with the [generate-omsp-responses](../bin/generate-omsp-responses) script. The OMSP key and its certificate chain are generated as part of the [setup-pki](../bin/setup-pki) or [setup-pki-ids](../bin/setup-pki-ids) script.

Changing the revocation status of a specific SW manifest is possible by manually changing the status in the respective JSON file in the omspFolder (data/omsp-raw). Supported revocation status are "valid", "outdated" (if newer version of the SW or its Manifest are available), and "revoked" (if security issues with the described SW are known or relevant security information provided in the manifest were detected to be false). If the OmspRequest includes SW manifest hashes that the OMSP server has no status for, it replies with the status "unknown".

### Include the URL Endpoint in the manifests
Manifests should define the "omspServer" as the URL of the OMSP endpoint of the running OMSP server. 
If a manifest does not contain an URL to an OMSP server, it is currently ignored, i.e., no revocation information is retrieved on the prover side and no revocation check conducted on the verifier side. 

The generation scripts for the SW manifests (in /bin/generate* and /bin/precompute*) include the optional parameter "--omsp <omsp endpoint>" to set the OMSP endpoint.

### Configure CMC to support manifest revocation
Usage of OMSP Stapling is optional in the CMC. It can be activated by setting the configuration option "useOmsp" to true (JSON config) or `--use-omsp` (CLI flag). The desired serialization format (JSON or CBOR) for the used OMSP-Responses needs to be specified using the "omspFormat" config option (JSON) or `--omsp-format` (CLI flag).

Acting as a prover, the CMC generates and sends OMSP Requests to all OMSP servers listed in the used SW Manifests. It stores the received OMSP Responses and transfers them as part of the *Metadata* in the Attestation Report.
OMSP Responses are only valid for a certain time period (currently 7 days) by including a NextUpdate date in the JSON structure (comparable to OCSP NextUpdate) and the CMC prover fetches new OMSP responses whenever the stored ones are older than two days.

Acting as a verifier, the CMC validates the signatures of the provided OmspResponses and checks the revocation status for all utilized SW manifests. It is currently built to fail remote attestation in case of issues with parsing/interpreting OMSP information, in case of "revoked" SW manifests and if revocation information about a SW manifest is missing ("unknown") or oudated (NextUpdate for manifest has passed). In case manifests themselves are marked as "outdated" (signaling that newer versions of the software or the manifest are available, but without security-critical issues about the current version), the remote attestation success status is set to "warn".