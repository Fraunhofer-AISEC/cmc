# Intel SGX Setup

Describes the setup to run the CMC within SGX enclaves.

## Prerequisites

The easiest way is to use our provided Docker container `cmc-docker`. In this case,
just SGX must be activated (ensure that `/dev/sgx_enclave` and `/dev/sgx_provision` is present).

If the docker container is not used, the [EGo framework](https://github.com/edgelesssys/ego)
and all [Intel SGX DCAP components](https://www.intel.com/content/www/us/en/developer/articles/guide/intel-software-guard-extensions-data-center-attestation-primitives-quick-install-guide.html).
must be installed manually. In this case, you can still follow this manual, just omit
`cmc-docker` before each command.

## SGX Setup

Creates the PKI and metadata for running the testtool with libapi (CMC integrated) within
an SGX enclave:
```sh
source env.bash
cmc-docker setup-cmc sgx
```

## SGX Build

Build the testtool with integrated CMC as SGX enclave:
```sh
cmc-docker make -C testtool egocmc
```

## PCCS

The Intel quoting enclave requires the Intel Provisioning Certification Service to run. If you
do not run your own service, you can start the docker container shipped with the CMC:
```sh
run-tdx-pccs
```

## SGX Run

`cmc-docker` can be prepended to any command. However, as the configuration files have relative
paths, it is easiest to simply enter the docker container and run everything from there:
```sh
cmc-docker
```

Run the estserver:
```sh
cd cmc/est/estserver
./estserver -config ../../example-setup/configs/est-server-conf.json
```

Run the testtool:
```sh
cd cmc/testtool

# Generate attestation report within enclave (configs folder is mounted into enclave)
ego run ./testtool -config configs/testtool-conf-sgx.json -mode generate

# Verify attestation report within enclave (can also be performed outside)
ego run ./testtool -config configs/testtool-conf-sgx.json -mode verify
```

Additional information for the enclave such as heapSize, mount points, security version (ISV SVN)
and enclave product ID (ISV Prod ID) can be specified in the enclave.json file.

See https://docs.edgeless.systems/ego/reference/config for more information.


---


## Intel SGX Manual Metadata Generation

The reference values for Intel SGX consist of a fingerprint of the Intel Root CA certificate,
the enclave product ID (ISV Prod ID), the security version of the enclave (ISVSVN), expected
enclave attributes (e.g. DEBUG, Mode64Bit, etc.), a hash of the enclave measurement (MRENCLAVE)
and a hash of the enclave signing key (MRSIGNER).

The Root CA certificate can be retrieved from the
[Intel API](https://api.portal.trustedservices.intel.com/content/documentation.html). ISV SVN and
ISV Prod ID are assigned by the enclave author. The EGo framework sets these values to 1 by default.
The MRENCLAVE and MRSIGNER values for an enclave can be retrieved via the EGo CLI tool with the
commands `ego uniqueid $ENCLAVE_PROGRAM` and `ego signerid $ENCLAVE_PROGRAM`.

For a complete example, see [generate-rtm-manifest-sgx](../bin/generate-rtm-manifest-sgx).