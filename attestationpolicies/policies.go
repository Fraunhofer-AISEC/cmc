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
	"encoding/json"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/robertkrimen/otto"
	"github.com/sirupsen/logrus"
)

var log = logrus.WithField("service", "policy-agent")

// JavaScriptValidator is a javascript implementation of the
// attestation report generic PolicyValidator interface
type JavaScriptValidator struct {
	policies []byte
}

// NewPolicyValidator creates a new JavaScriptValidator with custom policies.
// Custom policies are handed over as a byte array. This implementation
// accepts custom policies as javascript code. The javascript code
// can parse the VerificationResult in the variable 'json', i.e.:
//
//	var obj = JSON.parse(json);
//
// The javascript code must return a single boolean to indicate the
// success of the parsing. Logs can be output via: console.log()
// A very simple example of a custom Policy could look as follows:
//
//		var obj = JSON.parse(json);
//		var success = true;
//		if (obj.type != "Verification Result") {
//			console.log("Invalid type");
//			success = false;
//		}
//	    success
func NewPolicyValidator(policies []byte) *JavaScriptValidator {
	return &JavaScriptValidator{
		policies: policies,
	}
}

// Validate uses a javascript engine to validate the JavaScriptValidator's
// custom javascript policies against the verification result
func (p *JavaScriptValidator) Validate(result ar.VerificationResult) bool {

	log.Debugf("Validating custom javascript policies")

	vr, err := json.Marshal(result)
	if err != nil {
		log.Errorf("Failed to marshal verification result: %v", err)
		return false
	}

	// Create new javascript engine
	vm := otto.New()

	// Set variable json = vr
	vm.Set("json", string(vr))

	// Run javascript validation
	val, err := vm.Run(string(p.policies))
	if err != nil {
		log.Errorf("Failed run policy validation: %v", err)
		return false
	}

	// Retrieve result
	ok, err := val.ToBoolean()
	if err != nil {
		log.Errorf("Failed convert policy validation result: %v", err)
		return false
	}

	log.Debugf("Policy Validation: %v", ok)

	return ok
}
