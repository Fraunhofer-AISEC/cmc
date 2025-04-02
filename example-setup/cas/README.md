# README

This folder contains required CA certificates for making HTTPS requests: 
- SectigoRSAOrganizationValidationSecureServerCA.pem: CA for making requests to Intel TDX API services. 
Must be stored in Intel TDX CVMs in `/etc/ssl/certs` or mapped into Intel SGX enclaves (see [enclave-config](../enclave.json). 
