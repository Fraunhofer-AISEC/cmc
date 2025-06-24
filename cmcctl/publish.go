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

package main

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

func publishResultAsync(addr, file string, result *ar.VerificationResult, wg *sync.WaitGroup) {
	defer wg.Done()
	err := publishResult(addr, file, result)
	if err != nil {
		log.Warnf("Failed to asynchronously publish result: %v", err)
	}
}

func publishResult(addr, file string, result *ar.VerificationResult) error {

	if result == nil {
		return fmt.Errorf("will not publish result: not present")
	}
	if result.Prover == "" {
		return fmt.Errorf("will not publish result: prover is empty (this happens if connection could not be established)")
	}

	// Log the result
	if result.Success {
		log.Infof("SUCCESS: Verification for Prover %v (%v)", result.Prover, result.Created)
	} else {
		log.Warnf("FAILED: Verification for Prover %v (%v)", result.Prover, result.Created)
		result.PrintErr()
	}

	// Save the attestation result to file
	if file != "" {
		log.Debugf("Publishing result to file %q", file)
		data, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal verification result: %v", err)
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
	if addr != "" {
		log.Debugf("Publishing result to '%v'", addr)

		data, err := json.Marshal(*result)
		if err != nil {
			return fmt.Errorf("failed to marshal result: %v", err)
		}

		err = sendResult(addr, data)
		if err != nil {
			log.Warnf("Failed to publish: %v", err)
		}
	} else {
		log.Trace("Will not publish to remote server: no address specified")
	}

	return nil
}

func sendResult(addr string, result []byte) error {

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

	log.Debugf("Successfully published result: server responded with %v", resp.Status)

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
