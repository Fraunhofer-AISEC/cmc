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
generating and verifying attestation reports. The CMC exposes its functionality via multple APIs,
which are described in the following section.

![cmcd, drivers and cmcctl](./diagrams/architecture.drawio.svg)

The figure shows how the core components interact with each other. The main software components are:
- The *cmcd* daemon acts as an attestation prover and verifier: It collects evidence from different
hardware trust anchors and combines it with signed metadata describing the platform to produce
attestation reports. (prover), or validates the evidences against the metadata (verifier).
The *cmcd* provides a socket, a gRPC, as well as a CoAP REST API.
- The *cmcctl* can be used to control the *cmcd*, to generate and verify attestation reports and to
create exemplary attested tls and https connections.
- The *keymgr* for optinally creating and managing hardware keys and certificates for attested TLS
connections
- Drivers for trusted hardware to provide the evidences

## Attestation Reports

The overall exchanged data structure *Attestation Report* does not only contain evidences of
the software running on the platform, but also *metadata* in the form of *Manifests* and
*Descriptions*. This metadata describes the entire state of the platform and must be signed by
one or more trusted entities. This allows a verifier to validate the attestation report without
knowing the platform in advance. Examples and tools for creating the metadata can be found
in the [Example Setup](../example-setup/).

Core of the *Manifests* are the reference values, which contain the hashes of the software
artifacts running on the platform. We provide the [mrtool](../tools/mrtool/README.md) to precompute
the hashes of all artifacts based on reproducible software builds.

The overall structure of the attestation report can be seen in the following figure and is
described in detail in our [paper](https://dl.acm.org/doi/pdf/10.1145/3600160.3600171):

![Attestation Report](./diagrams/attestation-report.drawio.svg)

### Reference Values

The signed manifests contain reference-values that describe the legitimate software that is expected
to be running on the platform. The trust in the measurements comes from hardware-based measurement
technologies, such as TPMs or Confidential Computing technologies. The reference values for the
proving platform must be generated based on the used technology (TPM, Intel TDX/SGX, AMD SEV-SNP).

We provide the [mrtool](../tools/mrtool/README.md) for parsing and precomputing the reference values
based on reproducible builds.

### Metadata

Metadata is serialized in either [JSON](https://datatracker.ietf.org/doc/html/rfc8259) or
[CBOR](https://datatracker.ietf.org/doc/html/rfc8949) format and signed. Detailed description
on how to generate, sign and parse metadata is given in the [Metadata Description](./metadata.md).

## PKI

The following figure shows the Public Key Infrastructure (PKI) and Certificate Authority (CA) roles
in the CMC ecosystem. In practice, a single component may fulfill multiple roles.

The `cmcd` itself uses Attestation Key (AK) key-pair and corresponding certificates to sign the
hardware attestation reports (e.g. TPM or Intel TDX Quote). Depending on the used technology, the
private key usually resides in hardware and the certificate chain is provided by the manufacturer,
e.g., the Intel TDX PCK key and certificate chain or the AMD SEV-SNP VCEK key and certificate chain.

Furthermore, an arbitrary number of hardware-backed TLS key-pairs can generated and managed by the
`cmcd`. They can be used to establish attested TLS or HTTPS connections. For certificate enrollment,
EST or ACME can be used. We provide an `estserver` with additions to the EST protocol to not only
authenticate clients but perform attestation before issuing keys. If hardware-backed keys are not
required, attested TLS can be used with any user provided keys and certs.

![PKI](./diagrams/pki.drawio.svg)

| CA Name         | Required for                           | Certs           |
| --------------- | -------------------------------------- | --------------- |
| Trust Anchor CA | Embedding CA into attestation report   | AK Cert         |
| Metadata CA     | Verifying metadata                     | SW Signer certs |
| EST TLS CA      | Perform AK / IK certificate enrollment | EST TLS cert    |
| Identity CA     | Sign / Verify aTLS connections         | IK Cert         |

Each node requires trust anchor CAs (e.g., The AMD SEV-SNP or Intel SGX/TDX root CA, the TPM
manufacturer CA) if it shall be able to act as a prover. Verifying-only nodes do not require trust
anchor CAs, as the certificates are embedded in the *Context* and the valid CA fingerprints are
embdded into the *Manifests*. Trust Anchor CAs are either embedded into the evidence itself
(Intel TDX quote) or sent as part of the *Context*.

Each node requires metadata CAs, which are the root of trust for manifests and
reference values. *Metadata CAs can be fetched through the /metdatacacerts endpoint.*
Metadata CAs issue certificates to entities providing signed metadata and
reference values (e.g., software developers or certifiers).

If EST is used, an EST TLS CA for EST server authentication during initial certificate enrollment
is required. Nodes (i.e., EST clients) do not need to authenticate against the server, as a
trust anchor-based authentication and attestatoin is performed during certificate enrollment (e.g.,
TPM credential activation). This bootstrapping CA must be provisioned onto the node and measured
during attestation. The EST TLS CA is used for estserver authentication.

If TLS keys shall be enrolled via EST, each node requires an identity CA. This CA
can be fetched through querying the `/cacerts` EST server endpoint. The identity CA issues TLS keys
via EST endpoints (`/simpleenroll`, `/tpmcertifyenroll`, `/attestenroll`).


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

### cmcd, cmc
The CMC (*cmcd*) is the main component running on the platform. On request, the cmcd either
generates or verifies an attestation-report, i.e. the state of the platform. The cmcd provides
different APIs, such as gRPC, CoAP or simple sockets. For the generation and verification of
attestation reports, the *cmcd* relies on the *attestationreport* package. The functionality is
divided into the daemon (*cmcd*) and the *cmc* package, so that the *cmc* package can also be
used standalone.

### cmcctl
The *cmcctl* can generate and verify attestation reports and establish attested TLS as well as
attested HTTPS connections. For the latter, it makes use of the *attestedtls* and
*attestedhttp* packages. Usually, the *cmcctl* interacts with the *cmcd* via the *cmc* gRPC, CoAP or
socket API. However, the cmcctl can also act as a standalone application, i.e., integrate
all *cmc* functionality via their go API.

### attestationreport, prover, verifier
The *attestationreport*, *prover* and *verifier* packages provide a generic JSON/CBOR-based
serialization format to summarize the metadata describing the software running on the computer
platform. Enabling trust in this metadata requires a hardware-based Root-of-Trust (RoT) that
provides the possibility to store keys and measurements of the software running on the platform.
The *attestationreport* therefore implements generic interfaces. These interfaces must be
implemented by *drivers* that provide access to a hardware based RoT.

### keymgr

The *keymgr* is used to create and manage TLS keys and certificates. This package can be used, if
attested TLS connections shall be established via hardware-protected keys (e.g. TPM keys). The
*cmcd* provides an API for creating keys and certificates, as well as fetching certificates.

### tpmdriver
The *tpmdriver* package interfaces with a Trusted Platform Module (TPM) as the RoT.
The TPM is used to store cryptographic keys, store the software measurements (hashes) in its
Platform Configuration Registers (PCRs) during the *Measured Boot* and to generate and sign *Quotes*
which can be used to verify the platform state. Furthermore, the *tpmdriver* can use the *ima*
package interfacing with the kernel's Integrity Measurement Architecture (IMA) for obtaining
detailed measurement lists of the kernel modules, firmware and optionally further components
running on the platform.

### snpdriver
The *snpdriver* interfaces with the AMD SEV-SNP SP. It retrieves SNP measurements in the form of
an SNP attestation report as well as the certificate chain for this attestation report from the
respective AMD servers.

### sgxdriver
The *sgxdriver* interfaces with an Intel SGX-capable CPU. It retrieves SGX measurements in the form
of an SGX Quote signed by the SGX quoting enclave. It implements a small caching mechanism to fetch
and store the certificate chain used for report verification from the Intel SGX API.

### tdxdriver
The *tdxdriver* interfaces with an Intel TDX-capable CPU. It retrieves TDX measurements in the form
of a TDX Quote signed by the SGQ quoting enclave.

### swdriver
The *swdriver* creates keys in software for testing purposes. It can retrieve user space container
measurements.

### azuredriver
The *azuredriver* is used for Intel TDX and AMD SEV-SNP CVMs on Microsoft Azure. Azure employs a
vTPM within the CVM for runtime measurements. To obtain hardware reports (TDX or SNP), a nonce (user
data) is stored in a predefined vTPM NV index. The report is then retrieved from another predefined
NV index, which triggers fresh report generation. The azuredriver automatically detects whether
it is running on SNP or TDX and retrieves both the TDX quote or SNP report as well as the vTPM quote.

### estserver
During provisioning, the cmcd requires interaction with a provisioning server (*estserver*). The
server can provide certificates for software signing, perform the TPM *Credential Activiation* and
provision TPM certificates, and can provide the metadata (manifests and configurations) for the
*cmcd*. The server is mainly for demonstration purposes. In productive setups, its functionality
might be split onto different servers (e.g. an EST server and an internal metadata server).

### attestedtls
The *attestedtls* package provides attested TLS connections between two parties. After a tls
connection is established, additional steps are performed to obtain and verify the attestation
reports from the respective communication partner. Only then is the connection provided to the
server / client. For an example on how to integrate the library into own applications, the
*cmcctl* with its commands *listen* and *dial* can serve as an exemplary application.

### attestedhttp
The *attestedhttp* packages utilizes **attestedtls** to provide HTTPS client and server capabilities
to applications. The *cmcctl* with its modes *request* and *serve* can serve as an exemplary
application.

### api, grpcapi

These packages implement the different APIs the *cmcd* provides.

### measure

This package is used to record software container measurements.