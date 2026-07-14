// Copyright (c) 2021 - 2026 Fraunhofer AISEC
// Fraunhofer-Gesellschaft zur Foerderung der angewandten Forschung e.V.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package est

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/google/go-attestation/attest"
	"go.mozilla.org/pkcs7"
)

func CaCerts(client *http.Client, addr string, bearerToken []byte) ([]*x509.Certificate, error) {
	method := http.MethodGet
	endpoint := strings.TrimSuffix(addr, "/") + EndpointPrefix + CacertsEndpoint
	accepts := MimeTypePKCS7
	contentType := ""
	transferEncoding := ""

	resp, err := internal.Request(client, method, endpoint, accepts, contentType,
		transferEncoding, bearerToken, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to perform request: %w", err)
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read HTTP response body: %w", err)
	}

	// Extract certs from certs-only CMC Simple PKI Response [RFC5272]. The HTTP content-type of
	// "application/pkcs7-mime" is used. Sent with Content-Transfer-Encoding of "base64" [RFC2045]
	decoded, err := DecodeBase64(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 payload: %w", err)
	}

	log.Trace("Decoded base64 payload")

	p7, err := pkcs7.Parse(decoded)
	if err != nil {
		return nil, err
	}
	certs := p7.Certificates

	log.Tracef("Parsed %v certificates", len(certs))

	return certs, nil
}

func SimpleEnroll(client *http.Client, addr string, bearerToken []byte,
	csr *x509.CertificateRequest,
) (*x509.Certificate, error) {

	log.Debugf("Performing simple enroll for CSR %v", csr.Subject.CommonName)

	// PKCS#10 Request
	csrbase64 := EncodeBase64(csr.Raw)

	body := io.NopCloser(bytes.NewBuffer(csrbase64))

	method := http.MethodPost
	endpoint := strings.TrimSuffix(addr, "/") + EndpointPrefix + EnrollEndpoint
	accepts := MimeTypePKCS7
	contentType := MimeTypePKCS10
	transferEncoding := internal.HttpEncodingTypeBase64

	resp, err := internal.Request(client, method, endpoint, accepts, contentType,
		transferEncoding, bearerToken, body)
	if err != nil {
		return nil, fmt.Errorf("failed to perform request: %w", err)
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read HTTP response body: %w", err)
	}

	certs, err := ParseSimplePkiResponse(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to parse simple PKI response: %w", err)
	}

	return certs[0], nil
}

func TpmActivateEnroll(
	client *http.Client, addr string, bearerToken []byte,
	tpmManufacturer, ekCertUrl string,
	tpmMajor, tpmMinor int,
	csr *x509.CertificateRequest,
	akParams attest.AttestationParameters,
	ekPublic, ekCertDer []byte,
) ([]byte, []byte, []byte, error) {
	// Create string with TPM info required for the server to find the
	// correct EK certificate chain
	tpmInfo := fmt.Sprintf("%v;%v;%v", tpmManufacturer, tpmMajor, tpmMinor)

	buf, contentType, err := EncodeMultiPart(
		[]MimeMultipart{
			{ContentType: MimeTypeTextPlain, Data: tpmInfo},
			{ContentType: MimeTypeTextPlain, Data: ekCertUrl},
			{ContentType: MimeTypePKCS10, Data: csr},
			{ContentType: MimeTypeOctetStream, Data: akParams.Public},
			{ContentType: MimeTypeOctetStream, Data: akParams.CreateData},
			{ContentType: MimeTypeOctetStream, Data: akParams.CreateAttestation},
			{ContentType: MimeTypeOctetStream, Data: akParams.CreateSignature},
			{ContentType: MimeTypeOctetStream, Data: ekPublic},
			{ContentType: MimeTypeOctetStream, Data: ekCertDer},
		},
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to encode multipart: %w", err)
	}
	body := io.NopCloser(buf)

	endpoint := strings.TrimSuffix(addr, "/") + EndpointPrefix + TpmActivateEnrollEndpoint

	resp, err := internal.Request(client, http.MethodPost, endpoint, MimeTypePKCS7,
		contentType, internal.HttpEncodingTypeBase64, bearerToken, body)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to perform request: %w", err)
	}
	defer resp.Body.Close()

	var encryptedCredential []byte
	var encryptedSecret []byte
	var encryptedCert []byte

	_, err = DecodeMultipart(
		resp.Body,
		[]MimeMultipart{
			{ContentType: MimeTypeOctetStream, Data: &encryptedCredential},
			{ContentType: MimeTypeOctetStream, Data: &encryptedSecret},
			{ContentType: MimeTypePKCS7Enveloped, Data: &encryptedCert},
		},
		resp.Header.Get(internal.HttpContentTypeHeader),
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode multipart response: %w", err)
	}

	return encryptedCredential, encryptedSecret, encryptedCert, nil
}

func TpmCertifyEnroll(
	client *http.Client, addr string, bearerToken []byte,
	csr *x509.CertificateRequest,
	ikParams attest.CertificationParameters,
	akPublic []byte,
	report []byte,
) (*x509.Certificate, error) {
	log.Debugf("Performing TPM certify enroll for CSR %v", csr.Subject.CommonName)

	buf, contentType, err := EncodeMultiPart(
		[]MimeMultipart{
			{ContentType: MimeTypePKCS10, Data: csr},
			{ContentType: MimeTypeOctetStream, Data: ikParams.Public},
			{ContentType: MimeTypeOctetStream, Data: ikParams.CreateData},
			{ContentType: MimeTypeOctetStream, Data: ikParams.CreateAttestation},
			{ContentType: MimeTypeOctetStream, Data: ikParams.CreateSignature},
			{ContentType: MimeTypeOctetStream, Data: akPublic},
			{ContentType: MimeTypeOctetStream, Data: report},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to encode multipart: %w", err)
	}

	body := io.NopCloser(buf)

	method := http.MethodPost
	endpoint := strings.TrimSuffix(addr, "/") + EndpointPrefix + TpmCertifyEnrollEndpoint
	accepts := MimeTypePKCS7
	transferEncoding := internal.HttpEncodingTypeBase64

	resp, err := internal.Request(client, method, endpoint, accepts, contentType,
		transferEncoding, bearerToken, body)
	if err != nil {
		return nil, fmt.Errorf("failed to perform request: %w", err)
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read HTTP response body: %w", err)
	}

	certs, err := ParseSimplePkiResponse(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to parse simple PKI response: %w", err)
	}

	return certs[0], nil
}

func AttestEnroll(
	client *http.Client, addr string, bearerToken []byte,
	csr *x509.CertificateRequest,
	report []byte,
) (*x509.Certificate, error) {

	log.Debugf("Performing attest enroll for CSR %v", csr.Subject.CommonName)

	buf, contentType, err := EncodeMultiPart(
		[]MimeMultipart{
			{ContentType: MimeTypePKCS10, Data: csr},
			{ContentType: MimeTypeOctetStream, Data: report},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to encode multipart: %w", err)
	}

	body := io.NopCloser(buf)

	method := http.MethodPost
	endpoint := strings.TrimSuffix(addr, "/") + EndpointPrefix + AttestEnrollEndpoint
	accepts := MimeTypePKCS7
	transferEncoding := internal.HttpEncodingTypeBase64

	resp, err := internal.Request(client, method, endpoint, accepts, contentType,
		transferEncoding, bearerToken, body)
	if err != nil {
		return nil, fmt.Errorf("failed to perform request: %w", err)
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read HTTP response body: %w", err)
	}

	certs, err := ParseSimplePkiResponse(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to parse simple PKI response: %w", err)
	}

	return certs[0], nil
}
