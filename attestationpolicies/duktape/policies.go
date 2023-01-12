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
// #include "policies.h"
import "C"

import (
	"github.com/sirupsen/logrus"
)

var log = logrus.WithField("service", "duktape-policies")

// JsPolicyEngine is a javascript implementation of the
// attestation report generic PolicyValidator interface
type DukTapePolicyEngine struct {
	policies []byte
}

// NewDukTapePolicyEngine creates a new JsPolicyEngine with custom policies.
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
func NewDukTapePolicyEngine(policies []byte) *DukTapePolicyEngine {
	return &DukTapePolicyEngine{
		policies: policies,
	}
}

// Validate uses a the C duktape javascript engine to validate the
// custom javascript policies against the verification result
func (p *DukTapePolicyEngine) Validate(result []byte) bool {
	log.Debugf("Validating custom javascript policies")

	cResult := (*C.uint8_t)(C.CBytes(result))
	cResultLen := (C.size_t)(len(result))

	cPolicies := (*C.uint8_t)(C.CBytes(p.policies))
	cPoliciesLen := (C.size_t)(len(p.policies))

	// Call C duktape policy validation
	cRet := C.Validate(cResult, cResultLen, cPolicies, cPoliciesLen)
	ret := bool(cRet)

	return ret
}
