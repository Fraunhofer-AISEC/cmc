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

package main

// Install github packages with "go get [url]"
import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	// local modules

	"github.com/Fraunhofer-AISEC/cmc/api"
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
)

func publishResultAsync(addr string, result *ar.VerificationResult, wg *sync.WaitGroup) {
	defer wg.Done()
	publishResult(addr, result)
}

func publishResult(addr string, result *ar.VerificationResult) {

	if result == nil {
		log.Trace("Will not publish result: not present")
		return
	}
	if result.Prover == "" {
		log.Trace("Will not publish result: prover is empty (this happens if connection could not be established)")
		return
	}
	if addr == "" {
		log.Trace("Will not publish: no address specified")
		return
	}

	log.Tracef("Publishing result to '%v'", addr)

	data, err := json.Marshal(*result)
	if err != nil {
		log.Tracef("Failed to marshal result: %v", err)
		return
	}

	err = publishReport(addr, data)
	if err != nil {
		log.Tracef("Failed to publish: %v", err)
		return
	}
}

func publishReport(addr string, result []byte) error {

	if addr == "" {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, addr, bytes.NewBuffer(result))
	if err != nil {
		return fmt.Errorf("failed to create new http request with context: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("http post request failed: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != 201 {
		return fmt.Errorf("failed to publish result: server responded with %v: %v",
			resp.Status, string(data))
	}

	log.Tracef("Successfully published result: server responded with %v", resp.Status)

	return nil
}

func saveResult(file, addr string, r *ar.VerificationResult) error {

	// Log the result
	if r.Success {
		log.Infof("SUCCESS: Verification for Prover %v (%v)", r.Prover, r.Created)
	} else {
		log.Infof("FAILED: Verification for Prover %v (%v)", r.Prover, r.Created)
	}

	// Marshal the result (always as JSON for HTTP REST API and manual review)
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal verification result: %v", err)
	}

	// Save the Attestation Result to file
	if file != "" {
		os.WriteFile(file, data, 0644)
		log.Debugf("Wrote file %v", file)
	} else {
		log.Debug("No config file specified: will not save attestation report")
	}

	// Publish the attestation result if publishing address was specified
	if addr != "" {
		err := publishReport(addr, data)
		if err != nil {
			log.Warnf("failed to publish result: %v", err)
		}
		log.Debugf("Published attestation report to %v", addr)
	} else {
		log.Debug("No publish address specified: will not publish attestation report")
	}

	return nil
}

func saveReport(c *config, report []byte, nonce []byte) error {

	err := os.WriteFile(c.ReportFile, report, 0644)
	if err != nil {
		return fmt.Errorf("failed to write file %v: %v", c.ReportFile, err)
	}
	log.Infof("Wrote attestation response length %v: %v", len(report), c.ReportFile)

	// Save the nonce for the verifier
	err = os.WriteFile(c.NonceFile, nonce, 0644)
	if err != nil {
		return fmt.Errorf("failed to write file %v: %v", c.NonceFile, err)
	}
	log.Infof("Wrote nonce: %v", c.NonceFile)

	return nil
}

func loadReport(c *config) (*api.AttestationResponse, []byte, error) {
	nonce, err := os.ReadFile(c.NonceFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read faile %v: %w", c.NonceFile, err)
	}

	data, err := os.ReadFile(c.ReportFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read file %v: %w", c.ReportFile, err)
	}

	resp := new(api.AttestationResponse)
	err = c.apiSerializer.Unmarshal(data, resp)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal: %w", err)
	}

	return resp, nonce, nil
}
