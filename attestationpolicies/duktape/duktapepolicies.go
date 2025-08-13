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

package duktape

// #cgo CFLAGS: -Wall -std=c99
// #cgo LDFLAGS: -lm
// #include <stdint.h>
// #include <stdbool.h>
// #include <stdlib.h>
// #include <string.h>
// #include "policies.h"
import "C"

import (
	"encoding/json"
	"unsafe"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	"github.com/sirupsen/logrus"
)

var log = logrus.WithField("service", "duktape-policies")

// DukTypePolicyEngine is an implementation of the generic PolicyEngine interface for JavaScript
// policies based on the C duktape JavaScript engine
type DukTapePolicyEngine struct {
}

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
func (p *DukTapePolicyEngine) Validate(result *ar.VerificationResult, policies []byte, policyOverwrite bool) bool {

	log.Debugf("Validating custom javascript policies against verification result %q: %q",
		result.Prover, result.Summary.Status)

	vr, err := json.Marshal(result)
	if err != nil {
		log.Errorf("Failed to marshal verification result: %v", err)
		return false
	}

	cResult := (*C.uint8_t)(C.CBytes(vr))
	cResultLen := (C.size_t)(len(vr))

	cPolicies := (*C.uint8_t)(C.CBytes(policies))
	cPoliciesLen := (C.size_t)(len(policies))

	// Call C duktape policy validation
	cRet := C.Validate(cResult, cResultLen, cPolicies, cPoliciesLen)
	defer C.free(unsafe.Pointer(cRet))

	goStr := C.GoString(cRet)

	// Results can be boolean: In this case, the input result is not modified, but
	// just checked against the policies
	if goStr == "true" || goStr == "false" {
		log.Debug("Received boolean policy validation")
		ret := goStr == "true"
		log.Debugf("Policy Validation: %v", ret)
		return ret
	}

	// If explicitely configured, results can also be the modified result marshalled via
	// JSON.stringify(). In this case all properties of the result can be modified via policies
	// and we need to read back the result. This means, the policies engine can overwrite the
	// entire result
	if policyOverwrite {
		log.Debug("Received verification result policy validation")

		if err := json.Unmarshal([]byte(goStr), &result); err != nil {
			log.Errorf("Failed to unmarshal policy validation to verification result: %v", err)
			return false
		}
		return true
	} else {
		log.Debug("Policy overwrite is not configured. Only boolean return allowed")
		return false
	}
}
