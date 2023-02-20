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

package attestedtls

import (
	"crypto/tls"
	"fmt"

	"github.com/sirupsen/logrus"
)

var id = "0000"

var log = logrus.WithField("service", "atls")

func attestDialer(conn *tls.Conn, chbindings []byte, cc cmcConfig) error {

	if cc.mtls {
		log.Debug("Performing mutual attestation: Generating attestation report")
		// Obtain attestation report from local cmcd
		resp, err := cc.cmcApi.obtainAR(cc, chbindings)
		if err != nil {
			return fmt.Errorf("could not obtain dialer AR: %w", err)
		}

		// Send created attestation report to listener
		log.Trace("Sending attestation report to listener")
		err = Write(resp, conn)
		if err != nil {
			return fmt.Errorf("failed to send AR: %w", err)
		}
		log.Trace("Sent AR")
	} else {
		log.Debug("Skipping mTLS: server side authentication and attestation only")
	}

	// Wait for attestation report from listener
	log.Trace("Waiting for attestation report from listener")
	data, err := Read(conn)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	report, err := cc.cmcApi.parseARResponse(data)
	if err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	// Verify AR from listener with own channel bindings
	log.Trace("Verifying attestation report from listener")
	err = cc.cmcApi.verifyAR(chbindings, report, cc)
	if err != nil {
		return err
	}

	log.Trace("Attestation successful")

	return nil
}

func attestListener(conn *tls.Conn, chbindings []byte, cc cmcConfig) error {

	// Obtain own attestation report from local cmcd
	log.Trace("Generating listener attestation report")
	resp, err := cc.cmcApi.obtainAR(cc, chbindings)
	if err != nil {
		return fmt.Errorf("could not obtain listener AR: %w", err)
	}

	// Send own attestation report to dialer
	log.Trace("Sending own attestation report")
	err = Write(resp, conn)
	if err != nil {
		return fmt.Errorf("failed to send AR: %w", err)
	}

	// Wait for attestation report from dialer if mTLS is to be performed
	if cc.mtls {
		log.Debug("Performing mutual attestation: Waiting for dialer attestation report")
		data, err := Read(conn)
		if err != nil {
			return fmt.Errorf("failed to read response: %w", err)
		}

		report, err := cc.cmcApi.parseARResponse(data)
		if err != nil {
			return fmt.Errorf("failed to parse response: %w", err)
		}

		// Verify AR from dialer with own channel bindings
		log.Trace("Verifying attestation report from dialer...")
		err = cc.cmcApi.verifyAR(chbindings, report, cc)
		if err != nil {
			return err
		}
	} else {
		log.Debug("No mTLS performed")
	}

	log.Trace("Attestation successful")

	return nil
}
