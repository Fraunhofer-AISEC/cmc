// Copyright (c) 2021 - 2024 Fraunhofer AISEC
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

package publish

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	// local modules

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/sirupsen/logrus"
)

var (
	log = logrus.WithField("service", "publish")
)

func PublishAsync(resultsAddr, ocsfAddr, networkAddr string, token []byte, file string,
	result *ar.AttestationResult, wg *sync.WaitGroup,
	rootCas []*x509.Certificate, allowSystemCerts bool,
	clientCert *tls.Certificate,
) {
	defer wg.Done()
	if err := Publish(resultsAddr, ocsfAddr, networkAddr, token, file, result,
		rootCas, allowSystemCerts, clientCert); err != nil {
		log.Warnf("Failed to asynchronously publish: %v", err)
	}
}

func Publish(resultsAddr, ocsfAddr, networkAddr string, token []byte, file string,
	result *ar.AttestationResult,
	rootCas []*x509.Certificate, allowSystemCerts bool,
	clientCert *tls.Certificate,
) error {

	if result == nil {
		return fmt.Errorf("will not publish result: not present")
	}
	if result.Prover.Hostname == "" {
		return fmt.Errorf("will not publish result: prover is empty (this happens if connection could not be established)")
	}

	client, err := createClient(rootCas, allowSystemCerts, clientCert)
	if err != nil {
		return fmt.Errorf("failed to create HTTP client for publishing: %w", err)
	}

	// Log the result
	switch result.Summary.Status {
	case ar.StatusSuccess:
		log.Infof("SUCCESS: Verification for Prover %v (%v)", result.Prover.Hostname, result.Created)
	case ar.StatusWarn:
		log.Warnf("WARN: Verification for Prover %v (%v)", result.Prover.Hostname, result.Created)
	case ar.StatusFail:
		log.Warnf("FAILED: Verification for Prover %v (%v)", result.Prover.Hostname, result.Created)
		result.PrintErr()
	default:
		log.Warnf("FAILED: Unknown status %v for Prover %v (%v)", result.Summary.Status, result.Prover.Hostname, result.Created)
		result.PrintErr()
	}

	// Save the attestation result to file
	if file != "" {
		log.Debugf("Publishing result to file %q", file)
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal the attestation result: %v", err)
		}

		err = os.WriteFile(file, data, 0644)
		if err != nil {
			log.Warnf("Failed to write: %v", err)
		}
		log.Debugf("Wrote file %v", file)
	} else {
		log.Trace("Will not publish attestation result to file: no file specified")
	}

	// Send the attestation result to the specified server
	if resultsAddr != "" {
		log.Debugf("Publishing result to '%v'", resultsAddr)

		data, err := json.Marshal(*result)
		if err != nil {
			return fmt.Errorf("failed to marshal result: %v", err)
		}

		err = sendResult(client, resultsAddr, token, data)
		if err != nil {
			log.Warnf("Failed to publish: %v", err)
		}
	} else {
		log.Trace("Will not publish result to endpoint: no endpoint specified")
	}

	// Send OCSF detection findings to the specified server
	if ocsfAddr != "" {
		if result.Summary.Status != ar.StatusSuccess {
			findings := CreateDetectionFindings(result)
			log.Tracef("Publishing %v OCSF detection findings to %v", len(findings), ocsfAddr)
			for _, f := range findings {
				data, err := json.Marshal(f)
				if err != nil {
					log.Warnf("Failed to marshal OCSF finding: %v", err)
					continue
				}
				if err = sendResult(client, ocsfAddr, token, data); err != nil {
					log.Warnf("Failed to publish OCSF finding: %v", err)
					break
				}
			}
		}
	} else {
		log.Trace("Will not publish OCSF findings to endpoint: no endpoint specified")
	}

	// Send lightweight network event for graph visualization
	if networkAddr != "" {
		log.Tracef("Publishing network event to %v", networkAddr)
		if result.Verifier.Hostname != "" {
			event := CreateNetworkEvent(result)
			data, err := json.Marshal(event)
			if err != nil {
				log.Warnf("Failed to marshal network event: %v", err)
			} else if err = sendResult(client, networkAddr, token, data); err != nil {
				log.Warnf("Failed to publish network event: %v", err)
			}
		} else {
			log.Trace("Will not publish network event: verifier hostname is empty")
		}
	} else {
		log.Trace("Will not publish network event to endpoint: no endpoint specified")
	}

	return nil
}

func createClient(rootCas []*x509.Certificate, allowSystemCerts bool,
	clientCert *tls.Certificate,
) (*http.Client, error) {

	if len(rootCas) == 0 && !allowSystemCerts && clientCert == nil {
		log.Trace("Creating HTTP publishing client")
		return http.DefaultClient, nil
	}

	log.Trace("Creating HTTPS publishing client")

	tlsConfig := &tls.Config{}

	pool, err := internal.CreateCertPool(rootCas, allowSystemCerts)
	if err != nil {
		return nil, fmt.Errorf("failed to create cert pool: %w", err)
	}
	tlsConfig.RootCAs = pool

	if clientCert != nil {
		tlsConfig.Certificates = []tls.Certificate{*clientCert}
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}, nil
}

func sendResult(client *http.Client, addr string, token []byte, result []byte) error {

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, addr, bytes.NewBuffer(result))
	if err != nil {
		return fmt.Errorf("failed to create new http request with context: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	if token != nil {
		log.Trace("Adding bootstrap token to authorization header")
		req.Header.Set("Authorization", "Bearer "+string(token))
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("http post request failed: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != 201 && resp.StatusCode != 200 {
		return fmt.Errorf("failed to publish result: server responded with %v: %v",
			resp.Status, string(data))
	} else {
		log.Tracef("Success: Server responded with %v - %v", resp.StatusCode,
			http.StatusText(resp.StatusCode))
	}

	return nil
}

func SaveReport(reportFile, nonceFile string, report []byte, nonce []byte) error {

	err := os.WriteFile(reportFile, report, 0644)
	if err != nil {
		return fmt.Errorf("failed to write file %v: %v", reportFile, err)
	}
	log.Infof("Wrote attestation response length %v: %v", len(report), reportFile)

	// Save the nonce for the verifier
	err = os.WriteFile(nonceFile, nonce, 0644)
	if err != nil {
		return fmt.Errorf("failed to write file %v: %v", nonceFile, err)
	}
	log.Infof("Wrote nonce: %v", nonceFile)

	return nil
}

func LoadReport(reportFile, nonceFile string, s ar.Serializer) ([]byte, []byte, error) {
	nonce, err := os.ReadFile(nonceFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read faile %v: %w", nonceFile, err)
	}

	data, err := os.ReadFile(reportFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read file %v: %w", reportFile, err)
	}

	return data, nonce, nil
}
