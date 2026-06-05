// Copyright (c) 2026 Fraunhofer AISEC
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

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	mrand "math/rand/v2"
	"os"
	"regexp"
	"sync"
	"sync/atomic"
	"time"
)

const (
	NonceBufferSize uint          = 64
	AccountIdLength uint          = 8
	OrderTimeWindow time.Duration = 4 * time.Hour
	OrderLifeTime   time.Duration = 90 * 24 * time.Hour
)

func ValidateContact(contact string) bool {
	match, _ := regexp.MatchString("mailto:[a-zA-Z0-9]((-|_)?[a-zA-Z0-9])*@[a-zA-Z0-9]((-|_)?[a-zA-Z0-9])*\\.[a-zA-Z][a-zA-Z]+", contact)
	return match
}
func ValidateIdentifier(identifier string) bool {
	match, _ := regexp.MatchString("[a-zA-Z0-9](-?[a-zA-Z0-9])*(\\.[a-zA-Z0-9](-?[a-zA-Z0-9])*)*", identifier)
	return match
}

type nonceListEntry struct {
	nonce string
	next  *nonceListEntry
}
type AcmeNonceHandler struct {
	size uint
	list *nonceListEntry
	last *nonceListEntry
	mux  sync.Mutex
}

func (n *AcmeNonceHandler) AllocNext() string {
	n.mux.Lock()
	defer n.mux.Unlock()

	next := &nonceListEntry{
		nonce: rand.Text(),
	}
	if n.list == nil {
		n.last, n.list, n.size = next, next, n.size+1
		return next.nonce
	}

	n.last.next, n.last, n.size = next, next, n.size+1
	for ; n.size > NonceBufferSize; n.size-- {
		n.list = n.list.next
	}
	return next.nonce
}
func (n *AcmeNonceHandler) Check(nonce string) bool {
	n.mux.Lock()
	defer n.mux.Unlock()

	for prev, next := (*nonceListEntry)(nil), n.list; next != nil; prev, next = next, next.next {
		if next.nonce != nonce {
			continue
		}

		if prev == nil {
			n.list = next.next
		} else {
			prev.next = next.next
		}
		if next.next == nil {
			n.last = prev
		}
		return true
	}
	return false
}

func makeNewIdentifier() string {
	identifier, dict := "", "0123456789abcdefghijklmnopqrstuv"
	for range AccountIdLength {
		identifier += string(dict[mrand.IntN(len(dict))])
	}
	return identifier
}

type AccountStatus string
type OrderStatus string
type AuthStatus string

const (
	AccountStatusValid       AccountStatus = "valid"
	AccountStatusDeactivated AccountStatus = "deactivated"

	OrderStatusPending OrderStatus = "pending"
	OrderStatusReady   OrderStatus = "ready"
	OrderStatusValid   OrderStatus = "valid"
	OrderStatusInvalid OrderStatus = "invalid"

	AuthStatusPending     AuthStatus = "pending"
	AuthStatusValid       AuthStatus = "valid"
	AuthStatusExpired     AuthStatus = "expired"
	AuthStatusInvalid     AuthStatus = "invalid"
	AuthStatusDeactivated AuthStatus = "deactivated"
)

type AcmeAuthorization struct {
	Identifier    string
	Status        AuthStatus
	Token         string
	ChallengeType string
	Validated     string
}

type AcmeOrder struct {
	Identifier       string
	Status           OrderStatus
	RequestNotBefore string
	RequestNotAfter  string
	ExpiryTime       time.Time
	Authorizations   []AcmeAuthorization
	Certificate      []byte
}

func (o *AcmeOrder) UpdateOrder() {
	validCount, invalidCount := 0, 0

	// update the authorizations (terminal states cannot expire anymore)
	expired := time.Now().After(o.ExpiryTime)
	for i := range o.Authorizations {
		if expired &&
			o.Authorizations[i].Status != AuthStatusInvalid &&
			o.Authorizations[i].Status != AuthStatusDeactivated {
			o.Authorizations[i].Status = AuthStatusExpired
		}

		if o.Authorizations[i].Status == AuthStatusValid {
			validCount++
		} else if o.Authorizations[i].Status != AuthStatusPending {
			invalidCount++
		}
	}

	// update the overall order status (order becomes ready whenever at least one challenge per
	// authorization is valid - this server implementation only serves one challenge per
	// authorization; a finalized (valid) order keeps its status even after authorizations expire)
	if validCount == len(o.Authorizations) && o.Status == OrderStatusPending {
		o.Status = OrderStatusReady
	} else if invalidCount > 0 && o.Status != OrderStatusValid {
		o.Status = OrderStatusInvalid
	}
}

// AcmeAccount fields Identifier and TosAccepted are immutable after
// creation (set before the account is published to the shared map).
// They can be read without holding the mutex. The Jwk and Contacts
// fields may be updated (key rollover / contact update) and must be
// read under account.mux. The Deactivated flag is accessed via atomic
// operations. The orders map must only be accessed while holding mux.
type AcmeAccount struct {
	mux         sync.Mutex
	Deactivated atomic.Bool
	Jwk         string
	Identifier  string
	Contacts    []string
	TosAccepted bool
	orders      map[string]*AcmeOrder
}

func (a *AcmeAccount) UpdateContacts(contacts []string) {
	a.mux.Lock()
	a.Contacts = contacts
	a.mux.Unlock()
}

func (a *AcmeAccount) GetContacts() []string {
	a.mux.Lock()
	c := a.Contacts
	a.mux.Unlock()
	return c
}

func (a *AcmeAccount) CreateOrder(auths []AcmeAuthorization, notBefore, notAfter string, expiry time.Time) *AcmeOrder {
	a.mux.Lock()
	defer a.mux.Unlock()

	var identifier string
	for {
		identifier = makeNewIdentifier()
		if _, ok := a.orders[identifier]; !ok {
			break
		}
	}

	order := &AcmeOrder{
		Identifier:       identifier,
		Status:           OrderStatusPending,
		RequestNotBefore: notBefore,
		RequestNotAfter:  notAfter,
		ExpiryTime:       expiry,
		Authorizations:   auths,
	}
	a.orders[identifier] = order
	return order
}

func (a *AcmeAccount) OrderIDs() []string {
	a.mux.Lock()
	defer a.mux.Unlock()
	ids := make([]string, 0, len(a.orders))
	for id := range a.orders {
		ids = append(ids, id)
	}
	return ids
}

type AcmeState struct {
	mux      sync.Mutex
	Nonce    AcmeNonceHandler
	accounts map[string]*AcmeAccount
	CACert   []byte
	CAKey    *ecdsa.PrivateKey
	CAx509   *x509.Certificate
}

func NewAcmeState() *AcmeState {
	return &AcmeState{accounts: make(map[string]*AcmeAccount)}
}

func (s *AcmeState) LoadCA(certPath, keyPath string) error {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("reading CA certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("reading CA key: %w", err)
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return fmt.Errorf("no PEM block found in CA certificate file")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parsing CA certificate: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("no PEM block found in CA key file")
	}
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parsing CA key (expected EC private key): %w", err)
	}

	s.CACert = certPEM
	s.CAKey = key
	s.CAx509 = cert
	return nil
}

func (s *AcmeState) GenerateEphemeralCA() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generating CA key: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   "ACME Test Server Ephemeral CA",
			Organization: []string{"Fraunhofer AISEC"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("creating CA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("parsing generated CA certificate: %w", err)
	}

	s.CACert = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	s.CAKey = key
	s.CAx509 = cert
	return nil
}
func (s *AcmeState) LookupAccountByKey(jwk string) *AcmeAccount {
	s.mux.Lock()
	defer s.mux.Unlock()

	for _, acc := range s.accounts {
		if acc.Jwk == jwk {
			return acc
		}
	}
	return nil
}
func (s *AcmeState) FindOrCreateAccount(jwk string, contacts []string, tosAccepted bool) (*AcmeAccount, bool) {
	s.mux.Lock()
	defer s.mux.Unlock()

	for _, acc := range s.accounts {
		if acc.Jwk == jwk {
			return acc, false
		}
	}

	var identifier string
	for {
		identifier = makeNewIdentifier()
		if _, ok := s.accounts[identifier]; !ok {
			break
		}
	}

	account := &AcmeAccount{
		Jwk:         jwk,
		Identifier:  identifier,
		Contacts:    contacts,
		TosAccepted: tosAccepted,
		orders:      make(map[string]*AcmeOrder),
	}
	s.accounts[identifier] = account
	return account, true
}
func (s *AcmeState) LookupAccountById(id string) *AcmeAccount {
	s.mux.Lock()
	defer s.mux.Unlock()

	acc, ok := s.accounts[id]
	if !ok {
		return nil
	}
	return acc
}
func (s *AcmeState) ChangeAccountKey(account *AcmeAccount, oldJwk, newJwk string) *AcmeAccount {
	s.mux.Lock()
	defer s.mux.Unlock()

	if account.Jwk != oldJwk {
		return account
	}

	for _, acc := range s.accounts {
		if acc != account && acc.Jwk == newJwk {
			return acc
		}
	}

	account.mux.Lock()
	account.Jwk = newJwk
	account.mux.Unlock()

	return nil
}
