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

	err = publish(addr, data)
	if err != nil {
		log.Tracef("Failed to publish: %v", err)
		return
	}
}

func publish(addr string, result []byte) error {

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

func saveResult(file, addr string, result []byte) error {

	// Convert to human readable
	var out bytes.Buffer
	json.Indent(&out, result, "", "    ")

	// Save the Attestation Result to file
	if file != "" {
		os.WriteFile(file, out.Bytes(), 0644)
		log.Infof("Wrote file %v", file)
	} else {
		log.Debug("No config file specified: will not save attestation report")
	}

	// Publish the attestation result if publishing address was specified
	if addr != "" {
		err := publish(addr, result)
		if err != nil {
			log.Warnf("failed to publish result: %v", err)
		}
		log.Debug("Published attestation report")
	} else {
		log.Debug("No publish address specified: will not publish attestation report")
	}

	return nil
}
