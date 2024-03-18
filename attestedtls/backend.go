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
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

// Writes byte array to provided channel by first sending length information, then data.
// Used for transmitting the attestation reports between peers
func Write(msg []byte, c net.Conn) error {

	length := len(msg)
	lenbuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenbuf, uint32(length))

	n, err := c.Write(lenbuf)
	if err != nil {
		return fmt.Errorf("failed to write length to %v: %w", c.RemoteAddr().String(), err)
	}
	if n != len(lenbuf) {
		return fmt.Errorf("could only send %v of %v bytes to %v", n, len(lenbuf),
			c.RemoteAddr().String())
	}

	n, err = c.Write(msg)
	if err != nil {
		return fmt.Errorf("failed to write payload to %v: %w", c.RemoteAddr().String(), err)
	}
	if n != len(msg) {
		return fmt.Errorf("could only send %v of %v bytes to %v", n, len(msg),
			c.RemoteAddr().String())
	}

	return err
}

// Receives byte array from provided channel by first receiving length information, then data.
// Used for transmitting the attestation reports between peers
func Read(c net.Conn) ([]byte, error) {
	start := time.Now()

	lenbuf := make([]byte, 4)
	_, err := c.Read(lenbuf)

	if err != nil {
		return nil, fmt.Errorf("failed to receive message: no length: %v", err)
	}

	len := int(binary.BigEndian.Uint32(lenbuf)) // Max size of 4GB
	log.Tracef("TCP Message to be received: %v", len)

	if len == 0 {
		return nil, errors.New("message length is zero")
	}

	// Receive data in chunks of 1024 bytes as the Read function receives a maxium of 64K bytes
	// and the buffer must be longer, then append it to the final buffer
	buf := bytes.NewBuffer(nil)
	received := 0

	for {
		chunk := make([]byte, 64*1024)
		n, err := c.Read(chunk)
		received += n
		if err != nil {
			return nil, fmt.Errorf("failed to receive message: %w", err)
		}
		buf.Write(chunk[:n])

		// Abort as soon as we have read the expected data as signaled in the first 4 bytes
		// of the message
		if received == len {
			log.Trace("Received message")
			break
		}

		if time.Since(start).Seconds() >= 10 {
			log.Warn("Manual timeout during read")
			break
		}
	}
	return buf.Bytes(), nil
}
