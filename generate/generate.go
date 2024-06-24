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
	"errors"
	"fmt"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/sirupsen/logrus"
)

var log = logrus.WithField("service", "ar")

// Generate generates an attestation report with the provided
// nonce and manifests and descriptions metadata. The manifests and descriptions
// must be either raw JWS tokens in the JWS JSON full serialization
// format or CBOR COSE tokens. Takes a list of measurers providing a method
// for collecting  the measurements from a hardware or software interface
func Generate(nonce []byte, metadata [][]byte, measurers []ar.Driver, s ar.Serializer) ([]byte, error) {

	if s == nil {
		return nil, errors.New("serializer not specified")
	}

	// Create attestation report object which will be filled with the attestation
	// data or sent back incomplete in case errors occur
	report := ar.AttestationReport{
		Type: "Attestation Report",
	}

	if len(nonce) > 32 {
		return nil, fmt.Errorf("nonce exceeds maximum length of 32 bytes")
	}
	report.Nonce = nonce

	log.Debug("Adding manifests and descriptions to Attestation Report..")

	// Retrieve the manifests and descriptions
	log.Trace("Parsing ", len(metadata), " meta-data objects..")
	numManifests := 0
	for i := 0; i < len(metadata); i++ {

		// Extract plain payload (i.e. the manifest/description itself)
		data, err := s.GetPayload(metadata[i])
		if err != nil {
			log.Tracef("Failed to parse metadata object %v: %v", i, err)
			continue
		}

		// Unmarshal the Type field of the JSON file to determine the type for
		// later processing
		elem := new(ar.MetaInfo)
		err = s.Unmarshal(data, elem)
		if err != nil {
			log.Tracef("Failed to unmarshal data from metadata object %v: %v", i, err)
			continue
		}

		switch elem.Type {
		case "App Manifest":
			log.Debug("Adding App Manifest")
			report.AppManifests = append(report.AppManifests, metadata[i])
			numManifests++
		case "OS Manifest":
			log.Debug("Adding OS Manifest")
			report.OsManifest = metadata[i]
			numManifests++
		case "RTM Manifest":
			log.Debug("Adding RTM Manifest")
			report.RtmManifest = metadata[i]
			numManifests++
		case "Device Description":
			log.Debug("Adding Device Description")
			report.DeviceDescription = metadata[i]
		case "Company Description":
			log.Debug("Adding Company Description")
			report.CompanyDescription = metadata[i]
		}
	}

	if numManifests == 0 {
		log.Warn("Did not find any manifests for the attestation report")
	} else {
		log.Debug("Added ", numManifests, " manifests to attestation report")
	}

	log.Tracef("Retrieving measurements from %v measurers", len(measurers))
	for _, measurer := range measurers {

		// This actually collects the measurements. The methods are implemented
		// in the respective module (e.g. tpm module)
		log.Trace("Getting measurements from measurement interface..")
		measurement, err := measurer.Measure(nonce)
		if err != nil {
			return nil, fmt.Errorf("failed to get measurements: %v", err)
		}

		report.Measurements = append(report.Measurements, measurement)
		log.Tracef("Added %v to attestation report", measurement.Type)
	}

	log.Trace("Finished attestation report generation")

	// Marshal data to bytes
	data, err := s.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal the Attestation Report: %v", err)
	}

	return data, nil
}

// Sign signs the attestation report with the specified signer 'signer'
func Sign(report []byte, signer ar.Driver, s ar.Serializer) ([]byte, error) {
	return s.Sign(report, signer)
}
