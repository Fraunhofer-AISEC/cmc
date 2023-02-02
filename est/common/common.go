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

package common

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/textproto"
	"strings"

	log "github.com/sirupsen/logrus"
	"go.mozilla.org/pkcs7"
)

// URI constants
const (
	EndpointPrefix            = "/.well-known/est"
	CacertsEndpoint           = "/cacerts"
	CsrattrsEndpoint          = "/csrattrs"
	EnrollEndpoint            = "/simpleenroll"
	HealthCheckEndpoint       = "/healthcheck"
	ReenrollEndpoint          = "/simplereenroll"
	ServerkeygenEndpoint      = "/serverkeygen"
	TpmActivateEnrollEndpoint = "/tpmactivateenroll"
	TpmCertifyEnrollEndpoint  = "/tpmcertifyenroll"
	SnpEnrollEndpoint         = "/snpenroll"
)

// HTTP header constants
const (
	AcceptHeader             = "Accept"
	ContentTypeHeader        = "Content-Type"
	ContentTypeOptionsHeader = "X-Content-Type-Options"
	EncodingTypeBase64       = "base64"
	ParamValueCertsOnly      = "certs-only"
	ParamValueGenKey         = "server-generated-key"
	RetryAfterHeader         = "Retry-After"
	ServerHeader             = "Server"
	ServerKeyGenBoundary     = "estServerKeyGenBoundary"
	StrictTransportHeader    = "Strict-Transport-Security"
	TransferEncodingHeader   = "Content-Transfer-Encoding"
	UserAgentHeader          = "User-Agent"
)

// MIME type constants.
const (
	MimeParamBoundary      = "boundary"
	MimeParamSMIMEType     = "smime-type"
	MimeTypeCertificate    = "application/pkix-cert"
	MimeTypeCSRAttrs       = "application/csrattrs"
	MimeTypeJSON           = "application/json"
	MimeTypeMultipart      = "multipart/mixed"
	MimeTypeOctetStream    = "application/octet-stream"
	MimeTypePKCS10         = "application/pkcs10"
	MimeTypePKCS7          = "application/pkcs7-mime"
	MimeTypePKCS7CertsOnly = "application/pkcs7-mime; smime-type=certs-only"
	MimeTypePKCS7Enveloped = "application/pkcs7-mime; smime-type=enveloped-data"
	MimeTypePKCS7GenKey    = "application/pkcs7-mime; smime-type=server-generated-key"
	MimeTypePKCS8          = "application/pkcs8"
	MimeTypeProblemJSON    = "application/problem+json"
	MimeTypeTextPlain      = "text/plain"
	MimeTypeTextPlainUTF8  = "text/plain; charset=utf-8"
)

type MimeMultipart struct {
	ContentType string
	Data        interface{}
}

func EncodePkcs7CertsOnly(certs []*x509.Certificate) ([]byte, error) {
	var data []byte
	for i, cert := range certs {
		log.Tracef("Appending cert[%v]: %v", i, cert.Subject.CommonName)
		data = append(data, cert.Raw...)
	}
	return pkcs7.DegenerateCertificate(data)
}

func EncodeBase64(data []byte) []byte {
	enc := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(enc, data)
	return formatBase64(enc)
}

func DecodeBase64(data []byte) ([]byte, error) {
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
	n, err := base64.StdEncoding.Decode(decoded, data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}
	return decoded[:n], nil
}

// Break lines after 76 characters
func formatBase64(data []byte) []byte {
	lf := []byte{'\r', '\n'}

	b64len := 76
	srclen := len(data)
	dstlen := srclen + ((srclen/b64len)+1)*2

	buf := bytes.NewBuffer(make([]byte, 0, dstlen))

	for {
		linelen := len(data)
		if linelen == 0 {
			break
		} else if linelen > b64len {
			linelen = b64len
		}

		buf.Write(data[0:linelen])
		data = data[linelen:]
		buf.Write(lf)
	}

	return buf.Bytes()
}

func DecodeMultipart(r io.Reader, parts []MimeMultipart, ctypeHeader string) (int, error) {

	mediaType, params, err := mime.ParseMediaType(ctypeHeader)
	if err != nil {
		return 0, fmt.Errorf("failed to parse media type: %w", err)
	}

	if !strings.HasPrefix(mediaType, MimeTypeMultipart) {
		return 0, fmt.Errorf("invalid %s %s, must begin with %s", ctypeHeader,
			mediaType, MimeTypeMultipart)
	}

	mpr := multipart.NewReader(r, params[MimeParamBoundary])

	i := 0
	for _, part := range parts {
		p, err := mpr.NextPart()
		if err == io.EOF {
			break
		} else if err != nil {
			return 0, fmt.Errorf("failed to get multipart %v: %w", i, err)
		}
		defer p.Close()

		err = checkMediaType(p, part.ContentType, EncodingTypeBase64)
		if err != nil {
			return 0, fmt.Errorf("failed to verify part type %v: %w", i, err)
		}

		switch t := part.Data.(type) {
		case **x509.CertificateRequest:
			csr, err := ParsePkcs10Csr(p)
			if err != nil {
				return 0, fmt.Errorf("failed to parse CSR: %w", err)
			}
			*t = csr

		case *[]byte:
			data, err := io.ReadAll(p)
			if err != nil {
				return 0, fmt.Errorf("failed to read: %w", err)
			}
			decoded, err := DecodeBase64(data)
			if err != nil {
				return 0, fmt.Errorf("failed to decode: %w", err)
			}
			*t = decoded

		case *string:
			data, err := io.ReadAll(p)
			if err != nil {
				return 0, fmt.Errorf("failed to read: %w", err)
			}
			*t = string(data)

		case *uint64:
			data, err := io.ReadAll(p)
			if err != nil {
				return 0, fmt.Errorf("failed to read: %w", err)
			}
			decoded, err := DecodeBase64(data)
			if err != nil {
				return 0, fmt.Errorf("failed to decode: %w", err)
			}
			*t = binary.LittleEndian.Uint64(decoded)

		default:
			return 0, fmt.Errorf("unknown type %v %T", i, t)
		}

		i++
	}

	return i, nil
}

func EncodeMultiPart(parts []MimeMultipart) (*bytes.Buffer, string, error) {
	buf := bytes.NewBuffer([]byte{})
	w := multipart.NewWriter(buf)

	for i, p := range parts {
		var data []byte
		var err error

		switch t := p.Data.(type) {
		case []*x509.Certificate:
			data, err = EncodePkcs7CertsOnly(t)
			if err != nil {
				return nil, "", fmt.Errorf("failed to encode PKCS7 certs-only %v: %w", i, err)
			}
			data = EncodeBase64(data)

		case *x509.Certificate:
			data, err = EncodePkcs7CertsOnly([]*x509.Certificate{t})
			if err != nil {
				return nil, "", fmt.Errorf("failed to encode PKCS7 certs-only %v: %w", i, err)
			}
			data = EncodeBase64(data)

		case *x509.CertificateRequest:
			data = EncodeBase64(t.Raw)

		case []byte:
			data = EncodeBase64(t)

		case uint64:
			b := make([]byte, 8)
			binary.LittleEndian.PutUint64(b, t)
			data = EncodeBase64(b)

		case string:
			data = []byte(t)

		default:
			return nil, "", fmt.Errorf("unexpected multipart part body type %v: %T", i, t)
		}

		v := textproto.MIMEHeader{}
		v.Add(ContentTypeHeader, p.ContentType)
		v.Add(TransferEncodingHeader, EncodingTypeBase64)

		pw, err := w.CreatePart(v)
		if err != nil {
			return nil, "", fmt.Errorf("failed to create multipart writer part: %w", err)
		}

		if _, err := pw.Write(data); err != nil {
			return nil, "", fmt.Errorf("failed to write to multipart writer: %w", err)
		}
	}

	boundary := w.Boundary()

	err := w.Close()
	if err != nil {
		return nil, "", fmt.Errorf("failed to close multipart writer: %w", err)
	}

	return buf, fmt.Sprintf("%s; %s=%s", MimeTypeMultipart, MimeParamBoundary, boundary), nil
}

func checkMediaType(part *multipart.Part, contentType, encoding string) error {
	t, _, err := mime.ParseMediaType(part.Header.Get(ContentTypeHeader))
	if err != nil {
		return fmt.Errorf("failed to parse media type %s: %w",
			ContentTypeHeader, err)
	}
	if !strings.HasPrefix(contentType, t) {
		return fmt.Errorf("invalid %s %s, must begin with %s", ContentTypeHeader,
			t, contentType)
	}
	if part.Header.Get(TransferEncodingHeader) != encoding {
		return fmt.Errorf("%s part must be %s", encoding, TransferEncodingHeader)
	}
	return nil
}

func ParsePkcs10Csr(r io.Reader) (*x509.CertificateRequest, error) {

	payload, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read payload from request: %w", err)
	}

	log.Tracef("Parsing CSR:\n%v", string(payload))

	decoded, err := DecodeBase64(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode payload: %w", err)
	}

	csr, err := x509.ParseCertificateRequest(decoded)
	if err != nil {
		return nil, fmt.Errorf("failed to parse: %w", err)
	}

	err = csr.CheckSignature()
	if err != nil {
		return nil, fmt.Errorf("failed to verify signature of CSR: %w", err)
	}

	return csr, nil
}
