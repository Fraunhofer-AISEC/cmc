# Architecture

This is a brief description of the architecture and the components of the repository. For a more
detailed description, also refer to our [paper](https://dl.acm.org/doi/pdf/10.1145/3600160.3600171).

## Architecture Overview

The CMC is a framework that provides a unified interface to various attestation technologies for
generating and verifying attestation reports. This functionality is implemented in the `cmc`
package. Furthermore, the framework provides go packages for secure, attested channels:
attested TLS (`attestedtls`) and attested HTTPS (`attestedhttps`).

Applications aiming to establish attested secure channels might not have direct access to
the hardware (e.g., because they are running in containers or without the required privileges).
For this purpose, the framework provides the CMC daemon (`cmcd`) as the main application for
generating and verifying attestation. The CMC exposes its functionality via multple APIs, which are
described in the following section.

![CMC, drivers and exemplary testtool](./diagrams/architecture.drawio.svg)

The figure shows how the core components interact with each other. The main software components are:
- The *cmcd* daemon acts as an attestation prover and verifier: It collects measurements from
different hardware trust anchors and assembles this data together with signed metadata describing
the platform to an attestation report (prover), or validates the measurements against the metadata.
The *cmcd* provides a gRPC as well as a CoAP REST API.
- The testtool is an exemplary application that makes use of the *cmcd* to
generate and verify attestation reports and to create attested tls connections.
- Drivers for trusted hardware provide the attestation reports and, if available, key storage and
signing functionalities.

## Attestation Reports

The overall exchanged data structure *Attestation Report* does not only contain measurements of
the software running on the platform, but also *metadata* in the form of *Manifests* and
*Descriptions*. This metadata describes the entire state of the platform and must be signed by
one or more trusted entities. This allows a verifier to validate the attestation report without
knowing the platform in advance. Examples and tools for creating the metadata can be found
in the [Example Setup](../example-setup/).

Core of the *Manifests* are the reference values, which contain the hashes of the software
artifacts running on the platform. We aim to provide
[tools](https://github.com/Fraunhofer-AISEC/tpm-pcr-tools) to precompute the hashes of all artifacts
based on reproducible software builds.

The overall structure of the attestation report can be seen in the following figure and is
described in detail in our [paper](https://dl.acm.org/doi/pdf/10.1145/3600160.3600171):

![Attestation Report](./diagrams/attestation-report.drawio.svg)

### Metadata Templates

The example setup (folder `cmc/example-setup`) contains templates for the required metadata files
in JSON.

- **device.description.json**: Metadata describing the overall platform
- **manifest.description.json**: Embedded into device description, describes an instance of a manifest (i.e., a software layer or application)
- **manifest.json**: Template for a manifest containing reference values for a specific software layer or single application
- **company.description.json**: Optional, metadata describing the operater of the computing platform
- **device.config.json**: Signed local device configuration, contains e.g. the parameters for
the Certificate Signing Requests for the attestation and identity keys

### Serialization Format

The attestation report can be serialized to JSON and signed via JSON Web signatures (JWS), or to
CBOR and signed via CBOR Object Signing and Encryption (COSE).

As CBOR is a binary serialization format, the serialized data is not human-readable. Therefore, the
metadata templates are always in JSON. A [converter](../tools/metaconv/) is provided to convert the
metadata files to CBOR before signing them (see [Setup](./setup.md)).

### Reference Values

The signed manifests contain reference-values that describe the legitimate software that is expected
to be running on the platform. The trust in the measurements comes from hardware-based measurement
technologies, such as TPMs or Confidential Computing technologies. The reference values for the
proving platform must be generated based on the used technology (TPM, Intel TDX/SGX, AMD SEV-SNP).

We provide [tools]([tools](https://github.com/Fraunhofer-AISEC/tpm-pcr-tools) ) for parsing and
precomputing the reference values based on reproducible builds.

## Infrastructure Overview

The CMC framework supports attestation in the cloud (AMD SEV-SNP and Intel TDX platforms),
on the edge (e.g., Confidential Computing or TPM-based platforms) and also IoT / embedded
infrastructure (ARM Cortex-M TrustZone-based Initial Attestation Service, ARM Cortex-A with
OP-TEE and vTPM). For tiny embedded devices, we rely on an embdded CMC version implemented
in Rust (no_std).

Components can establish attestedTLS and attestedHTTPS connections. OSCORE/EDHOC support
for embedded devices is planned. Further TLS-based protocols can be integrated with
minimal effort.

![Infrastructure Overview](./diagrams/cmc-infrastructure.drawio.svg)

## Components
The following components correspond to the packages / directories of this repository.

__cmcd:__
The CMC daemon (*cmcd*) is the main component running on the platform. On request, the cmcd either
generates or verifies an attestation-report, i.e. the state of the platform. The cmcd provides
a gRPC interface to access its services (*grpcapi*), as well as a REST CoAP interface. For the
generation and verification of attestation reports, the *cmcd* relies on the *attestationreport*
package.

__attestationreport:__
The *attestationreport* package provides a generic JSON/CBOR-based serialization format to summarize
the meta-data describing the software running on the computer platform. Enabling trust in this
meta-data requires a hardware-based Root-of-Trust (RoT) that provides the possibility to store keys
and measurements of the software running on the platform. The *attestationreport* therefore
implements generic interfaces.
These interfaces must be implemented by *drivers* that provide access to a hardware based RoT.
Currently, this repository contains a *tpmdriver*, an *snpdriver* and an *swdriver*.

__tpmdriver:__
The *tpmdriver* package interfaces with a Trusted Platform Module (TPM) as the RoT.
The TPM is used to store cryptographic keys, store the software measurements (hashes) in its
Platform Configuration Registers (PCRs) during the *Measured Boot* and to generate and sign *Quotes*
which can be used to verify the platform state. Furthermore, the *tpmdriver* can use the *ima*
package interfacing with the kernel's Integrity Measurement Architecture (IMA) for obtaining
detailed measurement lists of the kernel modules, firmware and optionally further components
running on the platform.

__snpdriver:__
The *snpdriver* interfaces with the AMD SEV-SNP SP. It retrieves SNP measurements in the form of
an SNP attestation report as well as the certificate chain for this attestation report from the
respective AMD servers.

__sgxdriver:__
The *sgxdriver* interfaces with an Intel SGX-capable CPU. It retrieves SGX measurements in the form
of an SGX Quote signed by the SGX quoting enclave. It implements a small caching mechanism to fetch
and store the certificate chain used for report verification from the Intel SGX API.

__tdxdriver:__
The *tdxdriver* interfaces with an Intel TDX-capable CPU. It retrieves TDX measurements in the form
of a TDX Quote signed by the SGQ quoting enclave.

__swdriver:__
The *swdriver* creates keys in software for testing purposes. It can retrieve user space container
measurements.

__estserver:__
During provisioning, the cmcd requires interaction with a provisioning server (*estserver*). The
server can provide certificates for software signing, perform the TPM *Credential Activiation* and
provision TPM certificates, and can provide the metadata (manifests and configurations) for the
*cmcd*. The server is mainly for demonstration purposes. In productive setups, its functionality
might be split onto different servers (e.g. an EST server and an internal metadata server).

__attestedtls:__
The *attestedtls* package provides an exemplary protocol which shows how a connection between two
parties can be performed using remote attestation. After a tls connection is established, additional
steps are performed to obtain and verify the attestation reports from the respective communication
partner. Only then is the connection provided to the server / client. For an example on how to
integrate the library into own applications, the *testtool* with its modes *listen* and
*dial* can serve as an exemplary application.

__attestedhttp:__
The *attestedhttp packages utilizes **attestedtls** to provide HTTPS client and server capabilities
to applications. For an example on how to integrate the library into own applications, the
*testtool* with its modes *listen* and *dial* can serve as an exemplary application.

__testtool:__
The *testtool* can generate and verify attestation reports and establish attested TLS as well as
attested HTTPS connections. For the latter, it makes use of the *attestedtls* and
*attestedhttp* packages. The testtool can act as a standalone application, i.e., integrate
all *cmc* functionality via their go API, or as a tool that interacts with the
*cmcd* via a gRPC, CoAP or socket API for performing remote attestation.
