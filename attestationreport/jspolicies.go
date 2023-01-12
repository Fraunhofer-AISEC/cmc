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

//go:build !nodefaults || jspolicies

package attestationreport

import (
	"encoding/json"

	"github.com/Fraunhofer-AISEC/cmc/attestationpolicies/jspolicies"
)

type JsPolicyEngine struct{}

func init() {
	policyEngines[PolicyEngineSelect_JS] = JsPolicyEngine{}
}

func (p JsPolicyEngine) Validate(policies []byte, result VerificationResult) bool {
	vr, err := json.Marshal(result)
	if err != nil {
		log.Errorf("Failed to marshal verification result: %v", err)
		return false
	}
	engine := jspolicies.NewJsPolicyEngine(policies)
	return engine.Validate(vr)
}
