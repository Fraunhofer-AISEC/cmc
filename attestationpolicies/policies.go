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

package attestationpolicies

import (
	"errors"
	"fmt"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
)

// TODO name, comment
type Policies struct {
	Type                     string `json:"type"`
	ExpectCertificationLevel int    `json:"expectCertificationLevel"`
	ExpectTpmMeasurement     bool   `json:"expectTpmMeasurement"`
	ExpectSnpMeasurement     bool   `json:"expectSnpMeasurement"`
}

// TODO name, comment
type PolicyValidator struct {
	policies Policies
}

func NewPolicyValidator(p Policies) *PolicyValidator {
	return &PolicyValidator{
		policies: p,
	}
}

// TODO name, comment
func (p *PolicyValidator) Validate(result ar.VerificationResult) error {

	if p.policies.ExpectTpmMeasurement && result.MeasResult.TpmMeasResult == nil {
		return errors.New("policies validation failed: ExpectTpmMeasurement")
	}

	if p.policies.ExpectSnpMeasurement && result.MeasResult.SnpMeasResult == nil {
		return errors.New("policies validation failed: ExpectSnpMeasurement")
	}

	if p.policies.ExpectCertificationLevel > result.SwCertLevel {
		return fmt.Errorf("policies validation failed: ExpectCertificationLevel %v, got %v",
			p.policies.ExpectCertificationLevel, result.SwCertLevel)
	}

	// TODO add policies

	return nil
}
