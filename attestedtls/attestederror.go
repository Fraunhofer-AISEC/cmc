// Copyright (c) 2021 Fraunhofer AISEC
// Fraunhofer-Gesellschaft zur Foerderung der angewandten Forschung e.V.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package attestedtls

import (
	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
)

// Struct that holds verification result additional to the error
type AttestedError struct {
	err    error
	result ar.VerificationResult
}

// Error returns the error message as a string. This implements the Error interface
func (err AttestedError) Error() string {
	return err.err.Error()
}

// Unwrap returns the unwrapped error
func (err AttestedError) Unwrap() error {
	return err.err
}

// NewAttestedError creates an AttestedError using the provided error and attestation report
func NewAttestedError(r ar.VerificationResult, err error) AttestedError {
	return AttestedError{
		err:    err,
		result: r,
	}
}

// GetVerificationResult returns the verification result stored 	in the AttestedError
func (err AttestedError) GetVerificationResult() ar.VerificationResult {
	return err.result
}
