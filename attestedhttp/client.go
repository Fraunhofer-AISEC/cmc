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

package attestedhttp

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/sirupsen/logrus"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	atls "github.com/Fraunhofer-AISEC/cmc/attestedtls"
	"github.com/Fraunhofer-AISEC/cmc/cmc"
)

var log = logrus.WithField("service", "ahttps")

// Wrapper for net/http Transport
type Transport struct {

	// Wrapped http.Transport parameters
	TLSClientConfig        *tls.Config
	TLSHandshakeTimeout    time.Duration
	DisableKeepAlives      bool
	DisableCompression     bool
	MaxIdleConns           int
	MaxIdleConnsPerHost    int
	MaxConnsPerHost        int
	IdleConnTimeout        time.Duration
	ResponseHeaderTimeout  time.Duration
	ExpectContinueTimeout  time.Duration
	MaxResponseHeaderBytes int64
	WriteBufferSize        int
	ReadBufferSize         int

	// Some http.Transport parameters such as dial hooks are not exposed,
	// as we enforce aTLS as the underlying transport protocol

	// Additional aTLS parameters
	Attest        atls.AttestSelect
	MutualTls     bool
	CmcAddr       string
	CmcApi        atls.CmcApiSelect
	ApiSerializer ar.Serializer
	Cmc           *cmc.Cmc
	CmcPolicies   []byte
	IdentityCas   []*x509.Certificate
	MetadataCas   []*x509.Certificate
	ReadTimeout   time.Duration
	ResultCb      func(result *ar.VerificationResult)
}

// Wrapper for net/http Client
type Client struct {
	Transport     *Transport
	CheckRedirect func(req *http.Request, via []*http.Request) error
	Jar           http.CookieJar
	Timeout       time.Duration

	client *http.Client
}

// Wrapper for net/http client.Get()
func (c *Client) Get(url string) (resp *http.Response, err error) {

	err = prepareClient(c)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare client: %w", err)
	}

	log.Debugf("Performing aHTTPS GET to %v", url)

	return c.client.Get(url)
}

// Wrapper for net/http client.Do()
func (c *Client) Do(req *http.Request) (*http.Response, error) {

	err := prepareClient(c)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare client: %w", err)
	}

	log.Debugf("Performing aHTTPS %v to %v", req.Method, req.URL)

	return c.client.Do(req)
}

// Wrapper for net/http client.Post()
func (c *Client) Post(url, contentType string, body io.Reader) (resp *http.Response, err error) {

	err = prepareClient(c)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare client: %w", err)
	}

	log.Debugf("Performing aHTTPS POST with content type %v to %v", contentType, url)

	resp, err = c.client.Post(url, contentType, body)
	if err != nil {
		return nil, fmt.Errorf("aHTTPS POST request failed: %w", err)
	}

	log.Debugf("Client aHTTPS request completed")

	return resp, nil
}

// Wrapper for net/http client.Head()
func (c *Client) Head(url string) (resp *http.Response, err error) {

	err = prepareClient(c)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare client: %w", err)
	}

	log.Debugf("Performing aHTTPS HEAD to %v", url)

	return c.client.Head(url)
}

// Wrapper for net/http client.CloseIdleConnections()
func (c *Client) CloseIdleConnections() {

	if c.client == nil {
		log.Warn("Cannot close idle connections: client not initialized")
	}

	log.Debug("Cloding idle connections")

	c.client.CloseIdleConnections()
}

// Wrapper for net/http client.PostForm()
func (c *Client) PostForm(url string, data url.Values) (resp *http.Response, err error) {
	return c.client.PostForm(url, data)
}

// Prepare the client's underlying attested TLS connection
func prepareClient(c *Client) error {
	if c.client == nil {

		log.Debugf("Initializing new HTTP client")

		if c.Transport.ApiSerializer == nil {
			return fmt.Errorf("API serializer not configured")
		}

		// Create http.Transport from wrapper
		transport := &http.Transport{
			// User-specified HTTPS values
			TLSHandshakeTimeout:    c.Transport.TLSHandshakeTimeout, // ignored because of custom DialContext
			DisableKeepAlives:      c.Transport.DisableKeepAlives,
			DisableCompression:     c.Transport.DisableCompression,
			MaxIdleConns:           c.Transport.MaxIdleConns,
			MaxIdleConnsPerHost:    c.Transport.MaxIdleConnsPerHost,
			MaxConnsPerHost:        c.Transport.MaxConnsPerHost,
			ResponseHeaderTimeout:  c.Transport.ResponseHeaderTimeout,
			ExpectContinueTimeout:  c.Transport.ExpectContinueTimeout,
			MaxResponseHeaderBytes: c.Transport.MaxResponseHeaderBytes,
			WriteBufferSize:        c.Transport.WriteBufferSize,
			ReadBufferSize:         c.Transport.ReadBufferSize,
			TLSClientConfig:        c.Transport.TLSClientConfig, // Ignored because of custom DialContext
			IdleConnTimeout:        c.Transport.IdleConnTimeout,
			// Fixed custom TLS dial function to enforce aHTTPS
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if c.Transport.TLSClientConfig == nil {
					return nil, errors.New("failed to dial internal: no TLS config provided")
				}

				log.Debugf("Dialing TLS address: %v", addr)

				conn, err := atls.Dial("tcp", addr, c.Transport.TLSClientConfig,
					atls.WithApiSerializer(c.Transport.ApiSerializer),
					atls.WithAttest(c.Transport.Attest),
					atls.WithCmc(c.Transport.Cmc),
					atls.WithCmcAddr(c.Transport.CmcAddr),
					atls.WithCmcApi(c.Transport.CmcApi),
					atls.WithIdentityCas(c.Transport.IdentityCas),
					atls.WithMetadataCas(c.Transport.MetadataCas),
					atls.WithCmcPolicies(c.Transport.CmcPolicies),
					atls.WithMtls(c.Transport.MutualTls),
					atls.WithResultCb(c.Transport.ResultCb))
				if err != nil {
					return nil, fmt.Errorf("failed to dial server: %w", err)
				}
				if c.Transport.ReadTimeout != 0 {
					_ = conn.SetReadDeadline(time.Now().Add(c.Transport.ReadTimeout))
				}

				log.Debugf("Client-side aHTTPS connection established")

				return conn, err
			},
		}
		c.client = &http.Client{Transport: transport}
	}

	return nil
}
