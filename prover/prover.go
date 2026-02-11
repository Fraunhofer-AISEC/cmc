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

package prover

import (
	"crypto"
	"errors"
	"fmt"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/Fraunhofer-AISEC/cmc/drivers"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	"github.com/sirupsen/logrus"
)

var log = logrus.WithField("service", "ar")

// Generate generates an attestation report with the provided nonce and metadata. The metadata must
// either be in the form of JWS tokens infull serialization format or CBOR COSE tokens. The function
// takes a list of drivers for collecting the measurements from a hardware or software interface
func Generate(nonce []byte, cached []string, metadata map[string][]byte, drivers []drivers.Driver,
	s ar.Serializer, alg crypto.Hash,
) ([]byte, error) {

	log.Debugf("Generating attestation report with nonce %x", nonce)

	if s == nil {
		return nil, errors.New("serializer not specified")
	}

	encoding := ar.GetEncoding(s)

	// Use FQDN as attestation report name if possible,
	// otherwise omitempty
	hostname, _ := internal.Fqdn()

	// Create attestation report object which will be filled with the attestation
	// data or sent back incomplete in case errors occur
	report := &ar.AttestationReport{
		Version:  ar.GetReportVersion(),
		Type:     ar.TYPE_ATTESTATION_REPORT,
		Name:     hostname,
		Encoding: encoding,
		Context: ar.Context{
			Type:     ar.TYPE_CONTEXT,
			Alg:      alg.String(),
			Nonce:    nonce,
			Metadata: map[string][]byte{},
		},
	}

	log.Debug("Adding metadata to Attestation Report..")

	// Retrieve metadata
	log.Trace("Parsing ", len(metadata), " meta-data objects..")
	num := 0

	for hash, m := range metadata {

		// Extract plain payload
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

		log.Tracef("Adding metadata digest type %v: %v", header.Type, hash)
		report.Context.Digests = append(report.Context.Digests, hash)

		// Check if verifier has metadata item cached so it does not need to be sent
		log.Warnf("Check against %v cached items", len(cached))
		if internal.Contains(hash, cached) {
			log.Debugf("Metadata %v cached by verifier, do not add", hash)
		} else {
			log.Debugf("Metadata %v NOT cached by verifier, add", hash)
			report.Context.Metadata[hash] = m
		}

		num++
	}

	if num == 0 {
		log.Warn("Did not find any metadata items for the attestation report")
	} else {
		log.Debugf("Added %v metadata ids to attestation report", num)
	}

	// Retrieve collaterals for interpreting evidences
	log.Debugf("Retrieving collaterals from %v measurers", len(drivers))
	for _, driver := range drivers {
		log.Debugf("Getting collateral from %v", driver.Name())
		collateral, err := driver.GetCollateral()
		if err != nil {
			return nil, fmt.Errorf("failed to get collateral: %w", err)
		}
		report.Context.Collateral = append(report.Context.Collateral, collateral...)
	}

	// Prepare Attestation Report for collecting evidences with the context hash being
	// bound to the hardware evidence for context integrity
	evidenceNonce, err := report.PrepareContext(s, alg)
	if err != nil {
		return nil, fmt.Errorf("failed to prepare report context: %w", err)
	}

	// Retrieve hardware evidences
	for _, driver := range drivers {

		log.Debugf("Getting evidence from %v with evidence nonce %x", driver.Name(), evidenceNonce)
		evidence, err := driver.GetEvidence(evidenceNonce)
		if err != nil {
			return nil, fmt.Errorf("failed to get evidence: %w", err)
		}
		report.Evidences = append(report.Evidences, evidence...)
	}

	log.Debugf("Generated report with %v metadata digests and %v embedded items",
		len(report.Context.Digests), len(report.Context.Metadata))

	// Marshal data to bytes
	data, err := s.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal the Attestation Report: %v", err)
	}

	return data, nil
}
