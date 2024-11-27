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

package generate

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
// format or CBOR COSE tokens. Takes a list of measurers providing a method
// for collecting  the measurements from a hardware or software interface
func Generate(nonce []byte, cached []string, metadata map[string][]byte, measurers []ar.Driver, s ar.Serializer,
) (*ar.AttestationReport, error) {

	if s == nil {
		return nil, errors.New("serializer not specified")
	}

	// Create attestation report object which will be filled with the attestation
	// data or sent back incomplete in case errors occur
	report := &ar.AttestationReport{
		Type: "Attestation Report",
	}

	if len(nonce) > 32 {
		return nil, fmt.Errorf("nonce exceeds maximum length of 32 bytes")
	}

	log.Debug("Adding manifests and descriptions to Attestation Report..")

	// Retrieve the manifests and descriptions
	log.Trace("Parsing ", len(metadata), " meta-data objects..")
	numMetadata := 0
	numDigests := 0

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
		headerType := header.Type

		// Check if verifier has metadata item cached so it does not need to be sent
		var metadataDigest ar.MetadataDigest
		if internal.Contains(hash, cached) {
			log.Tracef("Metadata %v cached by verifier, do not add", hash)
			digest, err := hex.DecodeString(hash)
			if err != nil {
				log.Tracef("Failed to decode cached hash string: %v", err)
			} else {
				metadataDigest = ar.MetadataDigest{
					Type:   fmt.Sprintf("%v Digest", header.Type),
					Digest: digest,
				}
				headerType = metadataDigest.Type
			}
		}

		switch headerType {
		case "App Manifest":
			log.Debug("Adding App Manifest")
			report.AppManifests = append(report.AppManifests, m)
			numMetadata++
		case "App Manifest Digest":
			log.Debug("Adding App Manifest digest")
			report.AppManifestDigests = append(report.AppManifestDigests, metadataDigest)
			numDigests++
		case "OS Manifest":
			log.Debug("Adding OS Manifest")
			report.OsManifest = m
			numMetadata++
		case "OS Manifest Digest":
			log.Debug("Addign OS Manifest digest")
			report.OsManifestDigest = metadataDigest
			numDigests++
		case "RTM Manifest":
			log.Debug("Adding RTM Manifest")
			report.RtmManifest = m
			numMetadata++
		case "RTM Manifest Digest":
			log.Debug("Adding RTM Manifest digest")
			report.RtmManifestDigest = metadataDigest
			numDigests++
		case "Device Description":
			log.Debug("Adding Device Description")
			report.DeviceDescription = m
			numMetadata++
		case "Company Description":
			log.Debug("Adding Company Description")
			report.CompanyDescription = m
			numMetadata++
		case "Company Description Digest":
			log.Debug("Adding Company Description digest")
			report.CompanyDescriptionDigest = metadataDigest
			numDigests++
		}
	}

	if numMetadata == 0 {
		log.Warn("Did not find any metadata items for the attestation report")
	} else {
		log.Debugf("Added %v metadata items to attestation report", numMetadata)
	}

	log.Debugf("Added %v metadata digests to attestation report", numDigests)

	log.Debugf("Retrieving measurements from %v measurers", len(measurers))
	for _, measurer := range measurers {

		// Collect the measurements/evidence with the specified nonce from hardware/software.
		// The methods are implemented in the respective driver (TPM, SNP, ...)
		log.Debugf("Getting measurements from measurement interface..")
		measurement, err := measurer.Measure(nonce)
		if err != nil {
			return nil, fmt.Errorf("failed to get measurements: %v", err)
		}

		report.Measurements = append(report.Measurements, measurement)
		log.Debugf("Added %v to attestation report", measurement.Type)
	}

	log.Trace("Finished attestation report generation")

	return report, nil
}

// Sign signs the attestation report with the specified signer 'signer'
func Sign(report []byte, signer ar.Driver, s ar.Serializer) ([]byte, error) {
	return s.Sign(report, signer)
}
