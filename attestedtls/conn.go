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

package attestedtls

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const REJECT_AFTER_ADDTIME = (20 * time.Second) //kill connection if passed c.cc.ReattestAfterSeconds + REJECT_AFTER_ADDTIME
const REJECT_AFTER_ADDMESSAGES = 50             //kill connection if passed c.cc.ReattestAfterMessages + REJECT_AFTER_ADDMESSAGES

type Conn struct {
	//wrapper for net.Conn
	Conn net.Conn

	//base states for reattestaion
	lastAttestation time.Time
	messageCounter  uint32

	//for invoking reattestation
	isDialer   bool
	cc         CmcConfig
	chbindings []byte

	sentReattest     bool //to prevent spamming attestation reports
	receivedReattest bool
	reattestMutex    sync.Mutex
}

func NewConn(cc *CmcConfig, chbindings []byte, isDialer bool, conn net.Conn) Conn {
	return Conn{
		Conn:             conn,
		lastAttestation:  time.Now(),
		messageCounter:   0,
		isDialer:         isDialer,
		cc:               *cc,
		chbindings:       chbindings,
		sentReattest:     false,
		reattestMutex:    sync.Mutex{},
		receivedReattest: false,
	}
}

func (c *Conn) StartReattestTimer() error {
	if c.cc.ReattestAfterTime.Seconds() <= 0 {
		return fmt.Errorf("invalid Reattestation Duration")
	}
	ticker := time.NewTicker(c.cc.ReattestAfterTime)
	quit := make(chan struct{})

	go func() {
		for {
			select {
			case <-ticker.C:
				// terminates hanging ticker (connection already ended)
				if c.checkReject() {
					return
				}

				err := initiateReattest(c)
				if err != nil {
					log.Debug(err)
					return
				}

			case <-quit:
				ticker.Stop()
				return
			}
		}
	}()

	return nil
}

// Write implements net.Conn.
func (c *Conn) Write(b []byte) (n int, err error) {

	if c.checkReject() {
		return 0, fmt.Errorf("no reattestation received, terminate connection")
	}

	err = Write(b, c.Conn)
	if err != nil {
		return 0, err
	}

	//manage messageCounter if option is set
	if c.cc.ReattestAfterMessages > 0 {
		c.incrementMessageCounter()
		if c.getMessageCounter() >= uint32(c.cc.ReattestAfterMessages) {
			err = initiateReattest(c)
			if err != nil {
				log.Errorf("failed reattestation after message Limit, %v", err)
			}
		}
	}
	return len(b), err
}

func (c *Conn) Read(a []byte) (int, error) {

	b, err := Read(c.Conn)

	if err != nil {
		return 0, err
	}

	if c.checkReject() {
		return 0, fmt.Errorf("no reattestation received, terminate connection")
	}

	//manage messageCounter if option is set
	if c.cc.ReattestAfterMessages > 0 {
		c.incrementMessageCounter()
		if c.getMessageCounter() >= uint32(c.cc.ReattestAfterMessages) {
			err = initiateReattest(c)
			if err != nil {
				log.Errorf("failed reattestation after message Limit, %v", err)
			}
		}
	}

	//check for any incoming attestation reports
	magValIndex := bytes.Index(b, ATLS_MAGIC_VALUE[:])
	reverseMagValIndex := bytes.Index(b, REVERSE_ATLS_MAGIC_VALUE[:])
	if (magValIndex != -1) && (reverseMagValIndex != -1) && (magValIndex < reverseMagValIndex) {
		// buffer contains the magic value
		report, err := readValue(b[magValIndex:reverseMagValIndex+4], c.cc.Attest, c.isDialer, c.cc)
		if err != nil {
			var invalidATLScontentError InvalidATLScontentError
			if errors.As(err, &invalidATLScontentError) {
				//invalid cbor serialization, pass data as non atls
				log.Trace(err)

			} else {
				log.Tracef("Invalid attestation report: %v", err)
				return 0, err
			}
		} else {
			log.Trace("Validate Reattestation")
			//verify the attestation report
			err = validateAttestationReport(c.chbindings, c.cc, report, c.isDialer)
			if err != nil {
				return 0, err
			}

			//case when receiving a reattestation without having received a reattestation
			if c.sentReattest {
				c.resetReattest()
			} else {
				c.receivedReattest = true
			}

			//remove the attestation package, parse remaining data
			bnew := append(b[:magValIndex], b[reverseMagValIndex+4:]...)
			b = bnew

			//if no remaining data wait for the next package
			if len(bnew) == 0 {
				return c.Read(a)
			}
		}
	}

	//only forward the original message
	n := copy(a, b)
	if n < len(b) {
		return n, io.EOF
	}

	return len(b), err
}

func initiateReattest(c *Conn) error {

	//against spamming
	if c.sentReattest {
		return nil
	}

	c.reattestMutex.Lock()
	defer c.reattestMutex.Unlock()

	//recheck reattestation conditionings
	if !c.checkReattest() {
		return nil
	}

	c.sentReattest = true
	//do reattestation if (necessary)
	err := sendAttestationReport(c.Conn, c.chbindings, c.cc, c.isDialer)
	if err != nil {
		//still forwarding the byte
		c.sentReattest = false
		return err
	}

	//reset counter
	if c.receivedReattest {
		c.resetReattest()
	}

	return nil
}

// checkReattest check if enough time/ messages (spam protection)
func (c *Conn) checkReattest() bool {
	reattest := c.cc.ReattestAfterTime.Seconds() > 0 && time.Now().After(c.lastAttestation.Add(c.cc.ReattestAfterTime).Add(-REJECT_AFTER_ADDTIME)) //allow reattestation REJECT_AFTER_ADDTIME seconds earlier to account for delays
	reattest = reattest || (c.cc.ReattestAfterMessages > 0 && c.getMessageCounter() >= uint32(c.cc.ReattestAfterMessages))
	return reattest
}

func (c *Conn) checkReject() bool {
	reject := c.cc.ReattestAfterTime.Seconds() > 0 && time.Now().After(c.lastAttestation.Add(c.cc.ReattestAfterTime+REJECT_AFTER_ADDTIME))
	reject = reject || (c.cc.ReattestAfterMessages > 0 && c.getMessageCounter() >= uint32(c.cc.ReattestAfterMessages)+REJECT_AFTER_ADDMESSAGES)
	return reject
}

func (c *Conn) incrementMessageCounter() {
	atomic.AddUint32(&(c.messageCounter), 1)
}

func (c *Conn) getMessageCounter() uint32 {
	return atomic.LoadUint32(&c.messageCounter)
}

func (c *Conn) resetMessageCounter() {
	atomic.StoreUint32(&c.messageCounter, 0)
}

func (c *Conn) resetReattest() {
	//successful received and validated attestation report
	c.lastAttestation = time.Now()
	c.sentReattest = false
	c.receivedReattest = false
	c.resetMessageCounter()
}

func (c *Conn) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.Conn.RemoteAddr()
}

func (c *Conn) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)

}
func (c *Conn) Close() error {
	return c.Conn.Close()
}
