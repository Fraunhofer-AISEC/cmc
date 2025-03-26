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

package client

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"strings"

	"go.mozilla.org/pkcs7"

	est "github.com/Fraunhofer-AISEC/cmc/est/common"
	"github.com/Fraunhofer-AISEC/cmc/verifier"
	"github.com/sirupsen/logrus"
)

var log = logrus.WithField("service", "estclient")

type Client struct {
	client *http.Client
}

func NewClient(roots []*x509.Certificate) *Client {

	// Create Certpool for Root CAs
	rootpool := x509.NewCertPool()
	for _, r := range roots {
		rootpool.AddCert(r)
	}
	insecureSkipVerify := false
	if len(roots) == 0 {
		log.Debug("No EST server CA provided: Skipping certificate validation")
		insecureSkipVerify = true
	}

	// Read TLS certificate
	var tlsCerts []tls.Certificate

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:            rootpool,
				Certificates:       tlsCerts,
				InsecureSkipVerify: insecureSkipVerify,
			},
			DisableKeepAlives: false,
		},
	}

	return &Client{client: client}
}

func (c *Client) SetCAs(roots []*x509.Certificate) error {
	if len(roots) == 0 {
		return fmt.Errorf("no roots provided")
	}

	// Create Certpool for Root CAs
	rootpool := x509.NewCertPool()
	for _, r := range roots {
		rootpool.AddCert(r)
	}

	tp, ok := c.client.Transport.(*http.Transport)
	if !ok {
		return fmt.Errorf("internal error: failed to get transport")
	}

	tp.TLSClientConfig.InsecureSkipVerify = false
	tp.TLSClientConfig.RootCAs = rootpool

	return nil
}

func (c *Client) GetInsecureSkipVerify() bool {
	tp, ok := c.client.Transport.(*http.Transport)
	if !ok {
		// Simply return insecure set to true if assertion fails
		return true
	}

	return tp.TLSClientConfig.InsecureSkipVerify
}

func (c *Client) CaCerts(addr string) ([]*x509.Certificate, error) {

	method := http.MethodGet
	endpoint := strings.TrimSuffix(addr, "/") + est.EndpointPrefix + est.CacertsEndpoint
	accepts := est.MimeTypePKCS7
	contentType := ""
	transferEncoding := ""

	resp, err := request(c.client, method, endpoint, accepts, contentType, transferEncoding, nil)
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

func (c *Client) SimpleEnroll(addr string, csr *x509.CertificateRequest,
) (*x509.Certificate, error) {

	if c.GetInsecureSkipVerify() {
		return nil, fmt.Errorf("simple enroll requires server CAs to be configured")
	}

	// PKCS#10 Request
	csrbase64 := est.EncodeBase64(csr.Raw)

	body := io.NopCloser(bytes.NewBuffer(csrbase64))

	method := http.MethodPost
	endpoint := strings.TrimSuffix(addr, "/") + est.EndpointPrefix + est.EnrollEndpoint
	accepts := est.MimeTypePKCS7
	contentType := est.MimeTypePKCS10
	transferEncoding := est.EncodingTypeBase64

	resp, err := request(c.client, method, endpoint, accepts, contentType, transferEncoding, body)
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

func (c *Client) TpmActivateEnroll(
	addr, tpmManufacturer, ekCertUrl string,
	tpmMajor, tpmMinor int,
	csr *x509.CertificateRequest,
	akPublic, akCreateData, akCreateAttestation, akCreateSignature []byte,
	ekPublic, ekCertDer []byte,
) ([]byte, []byte, []byte, error) {

	if c.GetInsecureSkipVerify() {
		return nil, nil, nil, fmt.Errorf("enroll requires server CAs to be configured")
	}

	// Create string with TPM info required for the server to find the
	// correct EK certificate chain
	tpmInfo := fmt.Sprintf("%v;%v;%v", tpmManufacturer, tpmMajor, tpmMinor)

	buf, contentType, err := est.EncodeMultiPart(
		[]est.MimeMultipart{
			{ContentType: est.MimeTypeTextPlain, Data: tpmInfo},
			{ContentType: est.MimeTypeTextPlain, Data: ekCertUrl},
			{ContentType: est.MimeTypePKCS10, Data: csr},
			{ContentType: est.MimeTypeOctetStream, Data: akPublic},
			{ContentType: est.MimeTypeOctetStream, Data: akCreateData},
			{ContentType: est.MimeTypeOctetStream, Data: akCreateAttestation},
			{ContentType: est.MimeTypeOctetStream, Data: akCreateSignature},
			{ContentType: est.MimeTypeOctetStream, Data: ekPublic},
			{ContentType: est.MimeTypeOctetStream, Data: ekCertDer},
		},
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to encode multipart: %w", err)
	}
	body := io.NopCloser(buf)

	endpoint := strings.TrimSuffix(addr, "/") + est.EndpointPrefix + est.TpmActivateEnrollEndpoint

	resp, err := request(c.client, http.MethodPost, endpoint, est.MimeTypePKCS7, contentType, est.EncodingTypeBase64, body)
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
	addr string,
	csr *x509.CertificateRequest,
	ikPublic, ikCreateData, ikCreateAttestation, ikCreateSignature []byte,
	akPublic []byte,
) (*x509.Certificate, error) {

	if c.GetInsecureSkipVerify() {
		return nil, fmt.Errorf("enroll requires server CAs to be configured")
	}

	buf, contentType, err := est.EncodeMultiPart(
		[]est.MimeMultipart{
			{ContentType: est.MimeTypePKCS10, Data: csr},
			{ContentType: est.MimeTypeOctetStream, Data: ikPublic},
			{ContentType: est.MimeTypeOctetStream, Data: ikCreateData},
			{ContentType: est.MimeTypeOctetStream, Data: ikCreateAttestation},
			{ContentType: est.MimeTypeOctetStream, Data: ikCreateSignature},
			{ContentType: est.MimeTypeOctetStream, Data: akPublic},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to encode multipart: %w", err)
	}

	body := io.NopCloser(buf)

	method := http.MethodPost
	endpoint := strings.TrimSuffix(addr, "/") + est.EndpointPrefix + est.TpmCertifyEnrollEndpoint
	accepts := est.MimeTypePKCS7
	transferEncoding := est.EncodingTypeBase64

	resp, err := request(c.client, method, endpoint, accepts, contentType, transferEncoding, body)
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

func (c *Client) GetSnpCa(addr string, akType verifier.AkType) ([]*x509.Certificate, error) {

	// TODO mandate server authentication in the future

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
	endpoint := strings.TrimSuffix(addr, "/") + est.EndpointPrefix + est.SnpCaCertsEndpoint
	accepts := est.MimeTypePKCS7
	transferEncoding := est.EncodingTypeBase64

	resp, err := request(c.client, method, endpoint, accepts, contentType, transferEncoding, body)
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

func (c *Client) GetSnpVcek(addr string, ChipId [64]byte, Tcb uint64,
) (*x509.Certificate, error) {

	// TODO mandate server authentication in the future

	buf, contentType, err := est.EncodeMultiPart(
		[]est.MimeMultipart{
			{ContentType: est.MimeTypeOctetStream, Data: ChipId[:]},
			{ContentType: est.MimeTypeOctetStream, Data: Tcb},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to encode multipart: %w", err)
	}

	body := io.NopCloser(buf)

	method := http.MethodPost
	endpoint := strings.TrimSuffix(addr, "/") + est.EndpointPrefix + est.SnpVcekEndpoint
	accepts := est.MimeTypePKCS7
	transferEncoding := est.EncodingTypeBase64

	resp, err := request(c.client, method, endpoint, accepts, contentType, transferEncoding, body)
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
