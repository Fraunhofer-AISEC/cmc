// Copyright (c) 2021 Fraunhofer AISEC
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

package estclient

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"strings"

	"go.mozilla.org/pkcs7"

	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/provision/est"
	"github.com/Fraunhofer-AISEC/go-attestation/attest"
	"github.com/sirupsen/logrus"
)

var log = logrus.WithField("service", "estclient")

type Client struct {
	addr           string
	bootstrapToken []byte
	client         *http.Client
}

func New(addr string, serverTlsCas []*x509.Certificate, allowSystemCerts bool, token []byte) (*Client, error) {
	var err error

	// Create Certpool for Root CAs
	rootpool := x509.NewCertPool()
	if allowSystemCerts {
		log.Debug("Using system cert pool")
		rootpool, err = x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("failed to add system cert pool: %w", err)
		}
	}
	for _, r := range serverTlsCas {
		rootpool.AddCert(r)
	}

	if len(serverTlsCas) == 0 {
		return nil, fmt.Errorf("no EST server CA provided")
	}

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				// The client does authenticate the EST server
				RootCAs:            rootpool,
				InsecureSkipVerify: false,
				// The client does authenticate itself via attestation evidence and/or
				// a token as configured
				Certificates: nil,
			},
			DisableKeepAlives: false,
		},
	}

	return &Client{
		addr:           addr,
		bootstrapToken: token,
		client:         client,
	}, nil
}

func (c *Client) CaCerts() ([]*x509.Certificate, error) {

	method := http.MethodGet
	endpoint := strings.TrimSuffix(c.addr, "/") + est.EndpointPrefix + est.CacertsEndpoint
	accepts := est.MimeTypePKCS7
	contentType := ""
	transferEncoding := ""

	resp, err := request(c.client, method, endpoint, accepts, contentType, transferEncoding, nil, c.bootstrapToken)
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
	decoded, err := est.DecodeBase64(payload)
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

func (c *Client) SimpleEnroll(csr *x509.CertificateRequest) (*x509.Certificate, error) {

	// PKCS#10 Request
	csrbase64 := est.EncodeBase64(csr.Raw)

	body := io.NopCloser(bytes.NewBuffer(csrbase64))

	method := http.MethodPost
	endpoint := strings.TrimSuffix(c.addr, "/") + est.EndpointPrefix + est.EnrollEndpoint
	accepts := est.MimeTypePKCS7
	contentType := est.MimeTypePKCS10
	transferEncoding := est.EncodingTypeBase64

	resp, err := request(c.client, method, endpoint, accepts, contentType, transferEncoding, body, c.bootstrapToken)
	if err != nil {
		return nil, fmt.Errorf("failed to perform request: %w", err)
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read HTTP response body: %w", err)
	}

	certs, err := parseSimplePkiResponse(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to parse simple PKI response: %w", err)
	}

	return certs[0], nil
}

// akPublic, akCreateData, akCreateAttestation, akCreateSignature []byte,

func (c *Client) TpmActivateEnroll(
	tpmManufacturer, ekCertUrl string,
	tpmMajor, tpmMinor int,
	csr *x509.CertificateRequest,
	akParams attest.AttestationParameters,
	ekPublic, ekCertDer []byte,
) ([]byte, []byte, []byte, error) {

	// Create string with TPM info required for the server to find the
	// correct EK certificate chain
	tpmInfo := fmt.Sprintf("%v;%v;%v", tpmManufacturer, tpmMajor, tpmMinor)

	buf, contentType, err := est.EncodeMultiPart(
		[]est.MimeMultipart{
			{ContentType: est.MimeTypeTextPlain, Data: tpmInfo},
			{ContentType: est.MimeTypeTextPlain, Data: ekCertUrl},
			{ContentType: est.MimeTypePKCS10, Data: csr},
			{ContentType: est.MimeTypeOctetStream, Data: akParams.Public},
			{ContentType: est.MimeTypeOctetStream, Data: akParams.CreateData},
			{ContentType: est.MimeTypeOctetStream, Data: akParams.CreateAttestation},
			{ContentType: est.MimeTypeOctetStream, Data: akParams.CreateSignature},
			{ContentType: est.MimeTypeOctetStream, Data: ekPublic},
			{ContentType: est.MimeTypeOctetStream, Data: ekCertDer},
		},
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to encode multipart: %w", err)
	}
	body := io.NopCloser(buf)

	endpoint := strings.TrimSuffix(c.addr, "/") + est.EndpointPrefix + est.TpmActivateEnrollEndpoint

	resp, err := request(c.client, http.MethodPost, endpoint, est.MimeTypePKCS7, contentType,
		est.EncodingTypeBase64, body, c.bootstrapToken)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to perform request: %w", err)
	}
	defer resp.Body.Close()

	var encryptedCredential []byte
	var encryptedSecret []byte
	var encryptedCert []byte

	_, err = est.DecodeMultipart(
		resp.Body,
		[]est.MimeMultipart{
			{ContentType: est.MimeTypeOctetStream, Data: &encryptedCredential},
			{ContentType: est.MimeTypeOctetStream, Data: &encryptedSecret},
			{ContentType: est.MimeTypePKCS7Enveloped, Data: &encryptedCert},
		},
		resp.Header.Get(est.ContentTypeHeader),
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to decode multipart response: %w", err)
	}

	return encryptedCredential, encryptedSecret, encryptedCert, nil
}

func (c *Client) TpmCertifyEnroll(
	csr *x509.CertificateRequest,
	ikParams attest.CertificationParameters,
	akPublic []byte,
	report []byte,
	metadata [][]byte,
) (*x509.Certificate, error) {

	buf, contentType, err := est.EncodeMultiPart(
		[]est.MimeMultipart{
			{ContentType: est.MimeTypePKCS10, Data: csr},
			{ContentType: est.MimeTypeOctetStream, Data: ikParams.Public},
			{ContentType: est.MimeTypeOctetStream, Data: ikParams.CreateData},
			{ContentType: est.MimeTypeOctetStream, Data: ikParams.CreateAttestation},
			{ContentType: est.MimeTypeOctetStream, Data: ikParams.CreateSignature},
			{ContentType: est.MimeTypeOctetStream, Data: akPublic},
			{ContentType: est.MimeTypeOctetStream, Data: report},
			{ContentType: est.MimeTypeOctetStream, Data: internal.FlattenArray(metadata)},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to encode multipart: %w", err)
	}

	body := io.NopCloser(buf)

	method := http.MethodPost
	endpoint := strings.TrimSuffix(c.addr, "/") + est.EndpointPrefix + est.TpmCertifyEnrollEndpoint
	accepts := est.MimeTypePKCS7
	transferEncoding := est.EncodingTypeBase64

	resp, err := request(c.client, method, endpoint, accepts, contentType, transferEncoding,
		body, c.bootstrapToken)
	if err != nil {
		return nil, fmt.Errorf("failed to perform request: %w", err)
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read HTTP response body: %w", err)
	}

	certs, err := parseSimplePkiResponse(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to parse simple PKI response: %w", err)
	}

	return certs[0], nil
}

func (c *Client) CcEnroll(
	csr *x509.CertificateRequest,
	report []byte,
	metadata [][]byte,
) (*x509.Certificate, error) {

	buf, contentType, err := est.EncodeMultiPart(
		[]est.MimeMultipart{
			{ContentType: est.MimeTypePKCS10, Data: csr},
			{ContentType: est.MimeTypeOctetStream, Data: report},
			{ContentType: est.MimeTypeOctetStream, Data: internal.FlattenArray(metadata)},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to encode multipart: %w", err)
	}

	body := io.NopCloser(buf)

	method := http.MethodPost
	endpoint := strings.TrimSuffix(c.addr, "/") + est.EndpointPrefix + est.CcEnrollEndpoint
	accepts := est.MimeTypePKCS7
	transferEncoding := est.EncodingTypeBase64

	resp, err := request(c.client, method, endpoint, accepts, contentType, transferEncoding,
		body, c.bootstrapToken)
	if err != nil {
		return nil, fmt.Errorf("failed to perform request: %w", err)
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read HTTP response body: %w", err)
	}

	certs, err := parseSimplePkiResponse(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to parse simple PKI response: %w", err)
	}

	return certs[0], nil
}

func (c *Client) GetSnpCa(akType internal.AkType) ([]*x509.Certificate, error) {

	buf, contentType, err := est.EncodeMultiPart(
		[]est.MimeMultipart{
			{ContentType: est.MimeTypeOctetStream, Data: []byte{byte(akType)}},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to encode multipart: %w", err)
	}

	body := io.NopCloser(buf)

	method := http.MethodPost
	endpoint := strings.TrimSuffix(c.addr, "/") + est.EndpointPrefix + est.SnpCaCertsEndpoint
	accepts := est.MimeTypePKCS7
	transferEncoding := est.EncodingTypeBase64

	resp, err := request(c.client, method, endpoint, accepts, contentType, transferEncoding,
		body, c.bootstrapToken)
	if err != nil {
		return nil, fmt.Errorf("failed to perform request: %w", err)
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read HTTP response body: %w", err)
	}

	certs, err := parseSimplePkiResponse(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to parse simple PKI response: %w", err)
	}

	return certs, nil
}

func (c *Client) GetSnpVcek(chipId [64]byte, tcb uint64,
) (*x509.Certificate, error) {

	buf, contentType, err := est.EncodeMultiPart(
		[]est.MimeMultipart{
			{ContentType: est.MimeTypeOctetStream, Data: chipId[:]},
			{ContentType: est.MimeTypeOctetStream, Data: tcb},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to encode multipart: %w", err)
	}

	body := io.NopCloser(buf)

	method := http.MethodPost
	endpoint := strings.TrimSuffix(c.addr, "/") + est.EndpointPrefix + est.SnpVcekEndpoint
	accepts := est.MimeTypePKCS7
	transferEncoding := est.EncodingTypeBase64

	resp, err := request(c.client, method, endpoint, accepts, contentType, transferEncoding,
		body, c.bootstrapToken)
	if err != nil {
		return nil, fmt.Errorf("failed to perform request: %w", err)
	}
	defer resp.Body.Close()

	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read HTTP response body: %w", err)
	}

	certs, err := parseSimplePkiResponse(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to parse simple PKI response: %w", err)
	}

	return certs[0], nil
}

func request(
	client *http.Client,
	method, endpoint, accepts string,
	contentType, transferEncoding string,
	body io.Reader,
	token []byte,
) (*http.Response, error) {

	log.Debugf("Sending EST %v request to %v", method, endpoint)

	req, err := http.NewRequest(method, endpoint, body)
	if err != nil {
		return nil, fmt.Errorf("failed to make new HTTP request: %w", err)
	}

	if accepts != "" {
		req.Header.Set(est.AcceptHeader, accepts)
	}
	if contentType != "" {
		req.Header.Set(est.ContentTypeHeader, contentType)
	}
	if transferEncoding != "" {
		req.Header.Set(est.TransferEncodingHeader, transferEncoding)
	}
	if token != nil {
		log.Tracef("Adding bootstrap token %v to authorization header", string(token))
		req.Header.Set("Authorization", "Bearer "+string(token))
	} else {
		log.Tracef("Sending request without authorization token")
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to perform HTTP request: %w", err)
	}

	log.Debug("Finished EST HTTP request")

	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		payload, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read HTTP response body: %w", err)
		}
		return nil, fmt.Errorf("HTTP Server responded %v: %v", resp.Status, string(payload))
	}

	return resp, nil
}

// parseSimplePkiResponse extracts certs from certs-only CMC Simple PKI Response [RFC5272].
func parseSimplePkiResponse(data []byte) ([]*x509.Certificate, error) {

	decoded, err := est.DecodeBase64(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	p7, err := pkcs7.Parse(decoded)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS7: %w", err)
	}

	certs := p7.Certificates

	return certs, nil
}
