// Copyright (c) 2026 Fraunhofer AISEC
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
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"os"
	"path"
	"strings"
	"time"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/Fraunhofer-AISEC/cmc/provision"

	log "github.com/sirupsen/logrus"

	_ "github.com/mattn/go-sqlite3"
)

func (s *Server) handleRevocationRequest(w http.ResponseWriter, req *http.Request) {
	log.Debugf("Received /omsp request from %v", req.RemoteAddr)

	if strings.Compare(req.Method, "POST") != 0 {
		writeHttpErrorf(w, "Method %v not implemented for /omsp request", req.Method)
		return
	}

	var ser ar.Serializer
	var err error

	ct, _, _ := mime.ParseMediaType(req.Header.Get("Content-Type"))
	switch ct {
	case "application/json":
		ser, err = ar.NewJsonSerializer()
		if err != nil {
			writeHttpErrorf(w, "failed to generate JSON serializer: %v", err)
			return
		}
	case "application/cbor":
		ser, err = ar.NewCborSerializer()
		if err != nil {
			writeHttpErrorf(w, "failed to generate CBOR serializer: %v", err)
			return
		}
	default:
		writeHttpErrorf(w, "Content-Type %v not supported for /omsp request", req.Header["Content-Type"])
		return
	}

	payload, err := io.ReadAll(req.Body)
	if err != nil {
		writeHttpErrorf(w, "Failed to read HTTP request body: %v", err)
		return
	}

	var omspReq provision.OmspRequest
	err = ser.Unmarshal(payload, &omspReq)
	if err != nil {
		writeHttpErrorf(w, "failed to unmarshal OMSP request: %v", err)
		return
	}

	if omspReq.ArVersion != ar.GetReportVersion() {
		writeHttpErrorf(w, "version mismatch for AR version: %s vs. %s", omspReq.ArVersion, ar.GetReportVersion())
		return
	}

	var omspResp ar.Metadata
	omspResp.Type = ar.TYPE_OMSP_RESPONSE
	omspResp.Server = s.omspUrl
	omspResp.ProducedAt = time.Now().Format(time.RFC3339)

	//Retrieve OMSP Responses based on manifest hash from folder specified in config
	for _, hash := range omspReq.ManifestHashes {
		// Retrieve the OMSP responses
		log.Debugf("Retrieving OMSP response for manifest with hash %v", hash)

		// Check that the provided hash is a valid hex string to prevent path traversal attacks
		_, err := hex.DecodeString(hash)
		if err != nil {
			log.Debugf("Invalid manifest hash %v provided and ignored for response: %v", hash, err)
			writeHttpErrorf(w, "Invalid manifest hash provided: %v", hash)
			continue
		}
		file := path.Join(s.omspFolder, hash+".json")
		fileInfo, err := os.Stat(file)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				log.Tracef("File %v does not exist, i.e., manifest for this software is unknown", file)
				var singleResp ar.SingleOmspResponse
				singleResp.ManifestHash = hash
				singleResp.Status = ar.OmspStatusUnknown
				omspResp.Responses = append(omspResp.Responses, singleResp)
				continue
			} else {
				log.Warnf("Failed to retrieve information about file %v: %v", file, err)
				writeHttpErrorf(w, "Internal error during retrieval of OMSP response: %v", err)
			}
		}
		if fileInfo.Mode().IsRegular() {
			log.Tracef("Reading file %v", file)
			data, err := os.ReadFile(file)
			if err != nil {
				log.Warnf("Failed to read file %v", file)
				writeHttpErrorf(w, "Internal error during retrieval of OMSP response: %v", err)
				continue
			}
			var singleResp ar.SingleOmspResponse
			err = json.Unmarshal(data, &singleResp)
			if err != nil {
				log.Warnf("Failed to unmarshal OMSP response: %v", err)
				writeHttpErrorf(w, "Internal error during retrieval of OMSP response: %v", err)
				continue
			}
			omspResp.Responses = append(omspResp.Responses, singleResp)
		} else {
			log.Warnf("File for OMSP status of manifest with hash %v is not a regular file", hash)
			writeHttpErrorf(w, "Internal error during retrieval of OMSP response: %v", err)
		}
	}

	data, err := ser.Marshal(omspResp)
	if err != nil {
		writeHttpErrorf(w, "Failed to marshal OMSP request: %v", err)
		return
	}

	// Load OMSP key and sign JWS with the generated payload with it
	log.Tracef("Signing OMSP Response with omspKey")
	respBody, err := internal.Sign(data, s.omspKey, ser.String(), s.omspCaChain)
	if err != nil {
		log.Warnf("Failed to create signature: %v", err)
		http.Error(w, "Generating signature for OMSP responses failed", http.StatusBadRequest)
		return
	}

	err = sendResponse(w, ct, "", []byte(respBody))
	if err != nil {
		writeHttpErrorf(w, "Failed to send generated OMSP response: %v", err)
		return
	}
}
