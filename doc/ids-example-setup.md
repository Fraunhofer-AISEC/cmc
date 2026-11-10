# Quick Demo Setup IDS Use Case
The CMC repository contains a complete local example setup including a demo CA and all configurations and metadata matching the requirements for representing the certification scheme from the the International Data Spaces (IDS) .

The setup script `setup-cmc` with the `-i` flag sets up everything to quickly test remote
attestation with the IDS specific roles and CAs.

## Setup
> :warning: **Note:** You should run this only for testing on a development machine

The CMC must be [built and installed](./setup.md#build-and-install-the-cmc) first. The IDS PKI
additionally requires `sqlite3`.
```sh
git clone https://github.com/Fraunhofer-AISEC/cmc.git
cd cmc
source env.bash
setup-cmc -i tpm
```
The PKI and metadata are stored in `data/`.

## Run the CMC

```sh
# Start the EST server that supplies the certificates and metadata for the cmcd
estserver --config example-setup/configs/est-server-ids.toml

# Run the cmcd
sudo "$(command -v cmcd)" --config example-setup/configs/cmcd.toml --metadata https://127.0.0.1:9000/metadata-signed

# Run cmcctl to retrieve an attestation report (stored in current folder unless otherwise specified)
cmcctl generate

# Run cmcctl to verify the attestation report (stored in current folder unless otherwise specified)
cmcctl verify --root-cas data/pki/ca.pem --policies example-setup/policies/policies-ids.js
```
