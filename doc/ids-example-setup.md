# Quick Demo Setup IDS Use Case
The CMC repository contains a complete local example setup including a demo CA and all configurations and metadata matching the requirements for representing the certification scheme from the the International Data Spaces (IDS) .

The setup script `example-setup/setup-cmc-ids` sets up everything to quickly test remote attestation with the IDS specific roles and CAs.
It was tested on Ubuntu 22.04 LTS.

## Setup
> :warning: **Note:** You should run this only for testing on a development machine

```sh
git clone https://github.com/Fraunhofer-AISEC/cmc.git
<cmc-folder>/example-setup/setup-cmc-ids <cmc-folder> <metadata-folder>
```
with `<cmc-folder>` as the relative or absolute path to the cloned `cmc` repository and
`<metadata-folder>` as an arbitrary folder where metadata and configuration files are stored.

## Run the CMC

```sh
DATA=<metadata-folder>
# Start the EST server that supplies the certificates and metadata for the cmcd
server -config $DATA/est-server-conf-ids.json

# Build and run the cmcd
cmcd -config $DATA/cmcd-conf.json -addr https://127.0.0.1:9000/metadata-signed

# Run cmcctl to retrieve an attestation report (stored in current folder unless otherwise specified)
cmcctl -mode generate

# Run cmcctl to verify the attestation report (stored in current folder unless otherwise specified)
cmcctl -mode verify -ca $DATA/pki/ca.pem -policies $DATA/policies-ids.js
```
