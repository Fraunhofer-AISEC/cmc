# Architecture

This is a brief description of the architecture and the components of the repository. For a more
detailed description, also refer to our [paper](https://dl.acm.org/doi/pdf/10.1145/3600160.3600171).

## Architecture Overview

![CMC, drivers and exemplary testtool as well as interface descriptions](./overview.drawio.svg)

The figure shows how the core components interact with each other. The main software components are:
- The *cmcd* daemon acts as an attestation prover and verifier: It collects measurements from
different hardware trust anchors and assembles this data together with signed metadata describing
the platform to an attestation report (prover), or validates the measurements against the metadata.
The *cmcd* provides a gRPC as well as a CoAP REST API.
- The testtool is an exemplary application that makes use of the *cmcd* to
generate and verify attestation reports and to create attested tls connections.
- Drivers for trusted hardware provide the attestation reports and, if available, key storage and
signing functionalities.

## Basic Principle

The overall exchanged data structure *Attestation Report* does not only contain measurements of
the software running on the platform, but also metadata in the form of *Manifests* and
*Descriptions*. This metadata describes the entire state of the platform and must be signed by
one or more trusted entities. This allows a verifier to validate the attestation report without
knowing the platform in advance. Examples and tools for creating the metadata can be found
in the [Example Setup](../example-setup/).

The overall structure of the attestation report can be seen in the following figure and is
described in detail in our [paper](https://dl.acm.org/doi/pdf/10.1145/3600160.3600171):

![Attestation Report](./attestation_report.drawio.svg)

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
running on the platform. The *tpmdriver* can therefore act as *Measurement* as well as as
*Signer* interface.

__snpdriver:__
The *snpdriver* interfaces with the AMD SEV-SNP SP. It retrieves SNP measurements in the form of
an SNP attestation report as well as the certificate chain for this attestation report from the
respective AMD servers. Currently, it can only act as *Measurement* interface.

__swdriver:__
The *swdriver* simply creates keys in software for testing purposes and can be used as *Signer*
interface. **Note**: This should mainly be used for testing purposes.

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
partner. Only then is the connection provided to the server / client.

__testtool:__
The *testtool* can generate and verify attestation reports and establish attested TLS connections.
To estblish attestation TLS connections, the testtool makes use of the attested TLS package and thus
services provided by the cmcd to create an attested TLS connection. The client can be configured to
use one-sided or mutual attestation.
