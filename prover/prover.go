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

package prover

import (
	"encoding/hex"
	"errors"
	"fmt"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/sirupsen/logrus"
)

var log = logrus.WithField("service", "ar")

// Generate generates an attestation report with the provided
// nonce and manifests and descriptions metadata. The manifests and descriptions
// must be either raw JWS tokens in the JWS JSON full serialization
// format or CBOR COSE tokens. Takes a list of drivers providing a method
// for collecting  the measurements from a hardware or software interface
func Generate(nonce []byte, cached []string, metadata map[string][]byte, drivers []ar.Driver, s ar.Serializer,
) (*ar.AttestationReport, map[string][]byte, error) {

	metadataReturn := map[string][]byte{}

	if s == nil {
		return nil, nil, errors.New("serializer not specified")
	}

	// Create attestation report object which will be filled with the attestation
	// data or sent back incomplete in case errors occur
	report := &ar.AttestationReport{
		Version: ar.GetVersion(),
		Type:    "Attestation Report",
	}

	if len(nonce) > 32 {
		return nil, nil, fmt.Errorf("nonce exceeds maximum length of 32 bytes")
	}

	log.Debug("Adding manifests and descriptions to Attestation Report..")

	// Step 1: Retrieve manifests and descriptions
	log.Trace("Parsing ", len(metadata), " meta-data objects..")
	num := 0

	for hash, m := range metadata {

		// Extract plain payload (i.e. the manifest/description itself)
		data, err := s.GetPayload(m)
		if err != nil {
			log.Tracef("Failed to parse metadata object %v: %v", hash, err)
			continue
		}

		// Unmarshal the Type field of the JSON file to determine the type for
		// later processing
		header := new(ar.MetaInfo)
		err = s.Unmarshal(data, header)
		if err != nil {
			log.Tracef("Failed to unmarshal data from metadata object %v: %v", hash, err)
			continue
		}

		// Not all metadata needs to be sent
		if header.Type == "Device Config" {
			continue
		}

		digest, err := hex.DecodeString(hash)
		if err != nil {
			log.Tracef("Failed to decode cached hash string: %v", err)
			continue
		}
		metadataDigest := ar.MetadataDigest{
			Type:   header.Type,
			Digest: digest,
		}

		// Check if verifier has metadata item cached so it does not need to be sent
		if internal.Contains(hash, cached) {
			log.Tracef("Metadata %v cached by verifier, do not add", hash)
		} else {
			log.Tracef("Add metadata item %v", hash)
			metadataReturn[hash] = m
		}

		log.Debugf("Adding %v", metadataDigest.Type)
		report.Metadata = append(report.Metadata, metadataDigest)
		num++
	}

	if num == 0 {
		log.Warn("Did not find any metadata items for the attestation report")
	} else {
		log.Debugf("Added %v metadata ids to attestation report", num)
	}

	// Step 2: Retrieve measurements
	log.Debugf("Retrieving measurements from %v measurers", len(drivers))
	for _, driver := range drivers {

		// Collect the measurements/evidence with the specified nonce from hardware/software.
		// The methods are implemented in the respective driver (TPM, SNP, ...)
		log.Debugf("Getting measurements from measurement interface..")
		measurement, err := driver.Measure(nonce)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get measurements: %v", err)
		}

		report.Measurements = append(report.Measurements, measurement)
		log.Debugf("Added %v to attestation report", measurement.Type)
	}

	log.Trace("Finished attestation report generation")

	return report, metadataReturn, nil
}

// Sign signs the attestation report with the specified signer 'signer'
func Sign(report []byte, signer ar.Driver, s ar.Serializer, sel ar.KeySelection) ([]byte, error) {
	return s.Sign(report, signer, sel)
}
