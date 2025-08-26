// Copyright (c) 2024 Fraunhofer AISEC
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

// Contains the API definitions for the CoAP and socket API.
// The gRPC API is in a separate file
package api

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"

	log "github.com/sirupsen/logrus"
)

// Receive receives data from a socket with the following format
//
//	Len uint32 -> Length of the payload to be sent
//	Type uint32 -> Type of the payload
//	payload []byte -> encoded payload
func Receive(conn net.Conn) ([]byte, uint32, error) {

	// If unix domain sockets are used, set the write buffer size
	_, isUnixConn := conn.(*net.UnixConn)
	if isUnixConn {
		err := conn.(*net.UnixConn).SetReadBuffer(MaxUnixMsgLen)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to socket write buffer size %v", err)
		}
	}

	// Read header
	buf := make([]byte, 8)

	log.Tracef("Reading header length %v", len(buf))

	n, err := conn.Read(buf)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read header: %w", err)
	}
	if n != 8 {
		return nil, 0, fmt.Errorf("read %v bytes (expected 8)", n)
	}

	// Decode header to get length and type
	payloadLen := int(binary.BigEndian.Uint32(buf[0:4]))
	msgType := binary.BigEndian.Uint32(buf[4:8])

	if isUnixConn && payloadLen > MaxUnixMsgLen {
		return nil, 0, fmt.Errorf("cannot receive: payload size %v exceeds maximum size %v",
			payloadLen, MaxUnixMsgLen)
	}

	log.Tracef("Received header type %v. Receiving payload length %v", TypeToString(msgType), payloadLen)

	// Read payload
	payload := bytes.NewBuffer(nil)
	received := 0
	for {
		chunk := make([]byte, 128*1024)
		n, err = conn.Read(chunk)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to read payload: %w", err)
		}
		received += n
		payload.Write(chunk[:n])

		if received == payloadLen {
			break
		}
	}

	log.Tracef("Received payload length %v", payloadLen)

	return payload.Bytes(), msgType, nil
}

// Send sends data to a socket with the following format
//
//	Len uint32 -> Length of the payload to be sent
//	Type uint32 -> Type of the payload
//	payload []byte -> encoded payload
func Send(conn net.Conn, payload []byte, t uint32) error {

	// If unix domain sockets are used, set the write buffer size
	_, ok := conn.(*net.UnixConn)
	if ok {
		if len(payload) > MaxUnixMsgLen {
			return fmt.Errorf("cannot send: payload size %v exceeds maximum size %v",
				len(payload), MaxUnixMsgLen)
		}
		err := conn.(*net.UnixConn).SetWriteBuffer(MaxUnixMsgLen)
		if err != nil {
			return fmt.Errorf("failed to socket write buffer size %v", err)
		}
	}

	buf := make([]byte, 8)
	binary.BigEndian.PutUint32(buf[0:4], uint32(len(payload)))
	binary.BigEndian.PutUint32(buf[4:8], t)

	log.Tracef("Sending header length %v", len(buf))

	n, err := conn.Write(buf)
	if err != nil {
		return fmt.Errorf("failed to send header: %w", err)
	}
	if n != len(buf) {
		return fmt.Errorf("could only send %v of %v bytes", n, len(buf))
	}

	log.Tracef("Sending payload type %v length %v", TypeToString(t), uint32(len(payload)))

	n, err = conn.Write(payload)
	if err != nil {
		return fmt.Errorf("failed to send response: %w", err)
	}
	if n != len(payload) {
		return fmt.Errorf("could only send %v of %v bytes", n, len(payload))
	}

	return nil
}
