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

package attestationreport

import (
	"bytes"
)

func VerifySwMeasurements(swMeasurements []Measurement, refVals []ReferenceValue) ([]MeasurementResult, bool) {

	log.Trace("Verifying SW measurements")

	swMeasurementResults := make([]MeasurementResult, 0)
	ok := true

	// Check that every reference value is reflected by a measurement
	for _, v := range refVals {
		result := MeasurementResult{}
		result.Summary.Success = false
		result.SwResult.VerName = v.Name
		found := false
		for _, swm := range swMeasurements {
			if bytes.Equal(swm.Sha256, v.Sha256) {
				result.SwResult.MeasName = swm.Description
				result.Summary.Success = true
				found = true
				break
			}
		}
		if !found {
			log.Tracef("no SW Measurement found for SW Reference Value %v (hash: %v)", v.Name, v.Sha256)
			result.Summary.SetErr(RefValNoMatch)
			ok = false
		}
		swMeasurementResults = append(swMeasurementResults, result)
	}

	// Check that every measurement is reflected by a reference value
	for _, swM := range swMeasurements {
		found := false
		for _, swV := range refVals {
			if bytes.Equal(swM.Sha256, swV.Sha256) {
				found = true
				break
			}
		}
		if !found {
			result := MeasurementResult{}
			result.SwResult.MeasName = swM.Description
			log.Tracef("no SW Reference Value found for SW Measurement: %v", swM.Sha256)
			result.Summary.SetErr(MeasurementNoMatch)
			swMeasurementResults = append(swMeasurementResults, result)
			ok = false
		}
	}

	return swMeasurementResults, ok
}
