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

package jspolicies

import (
	"encoding/json"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/robertkrimen/otto"
	"github.com/sirupsen/logrus"
)

var log = logrus.WithField("service", "jspolicies")

// JsPolicyEngine is an implementation of the generic PolicyEngine interface for JavaScript policies
// based on the golang otto JavaScript engine
type JsPolicyEngine struct{}

// Validate uses a javascript engine to validate custom policies against the verification result.
// Custom policies are handed over as a string. This implementation accepts custom policies
// as javascript code. The javascript code can parse the VerificationResult in the variable
// 'json', i.e.:
//
//	var obj = JSON.parse(json);
//
// The javascript code can either return a single boolean to indicate the success of the validation.
// A very simple example of a custom Policy could look as follows:
//
//	var obj = JSON.parse(json);
//	var success = true;
//	if (obj.type != "Verification Result") {
//		success = false;
//	}
//	success
//
// Or the javascript code can either return the marshalled verification result
// A simple validation could then look as follows:
//
//	var obj = JSON.parse(json);
//	obj.summary.status = "warn"
//	var ret = JSON.stringify(obj);
//	ret
func (p *JsPolicyEngine) Validate(result *ar.VerificationResult, policies []byte, policyOverwrite bool) bool {

	log.Debugf("Validating custom javascript policies against verification result %q: %q",
		result.Prover, result.Summary.Status)

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
	val, err := vm.Run(policies)
	if err != nil {
		log.Errorf("Failed run policy validation: %v", err)
		return false
	}

	// Results can be boolean: In this case, the input result is not modified, but
	// just checked against the policies
	if val.IsBoolean() {
		log.Debug("Received boolean policy validation")
		ok, err := val.ToBoolean()
		if err != nil {
			log.Errorf("failed convert policy validation result to bool: %v", err)
			return false
		}

		log.Debugf("Policy Validation: %v", ok)

		return ok
	}

	// Results can also be the modified result marshalled via
	// JSON.stringify(). In this case all properties of the result can be modified via policies
	// and we need to read back the result. This means, the policies engine can overwrite the
	// entire result
	if val.IsString() {
		// Overwriting results must explicitly be configured
		if policyOverwrite {
			log.Debug("Received verification result policy validation")
			r, err := val.ToString()
			if err != nil {
				log.Errorf("Failed convert policy validation result to bool: %v", err)
				return false
			}
			err = json.Unmarshal([]byte(r), result)
			if err != nil {
				log.Errorf("Failed to unmarshal policy validation to verification result: %v", err)
				return false
			}
			return true
		} else {
			log.Debug("Policy overwrite is not configured. Only boolean return allowed")
			return false
		}
	}

	log.Debugf("Failed to convert policy validation result: unsupported type")

	return false
}
