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
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	mrand "math/rand/v2"
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

	IssueTimeout           time.Duration = 10 * time.Minute
	UpstreamRequestTimeout time.Duration = 60 * time.Second
	FinalizeGracePeriod    time.Duration = 1 * time.Second
	ProcessingRetryAfter   time.Duration = 5 * time.Second
)

func ValidateContact(contact string) bool {
	// rudimentary and in no way complete mail verification scheme
	match, _ := regexp.MatchString("mailto:[a-zA-Z0-9]((-|_)?[a-zA-Z0-9])*@[a-zA-Z0-9]((-|_)?[a-zA-Z0-9])*\\.[a-zA-Z][a-zA-Z]+", contact)
	return match
}
func ValidateIdentifier(identifier string) bool {
	// rudimentary and not complete identifier verification scheme
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

	OrderStatusPending    OrderStatus = "pending"
	OrderStatusReady      OrderStatus = "ready"
	OrderStatusProcessing OrderStatus = "processing"
	OrderStatusValid      OrderStatus = "valid"
	OrderStatusInvalid    OrderStatus = "invalid"

	AuthStatusPending     AuthStatus = "pending"
	AuthStatusValid       AuthStatus = "valid"
	AuthStatusExpired     AuthStatus = "expired"
	AuthStatusInvalid     AuthStatus = "invalid"
	AuthStatusDeactivated AuthStatus = "deactivated"
)

type AcmeChallenge struct {
	Type      string
	Token     string
	Status    AuthStatus
	Validated string
}

type AcmeAuthorization struct {
	Identifier string
	Status     AuthStatus
	Challenges []AcmeChallenge
}

type AcmeOrder struct {
	Identifier       string
	Status           OrderStatus
	RequestNotBefore string
	RequestNotAfter  string
	ExpiryTime       time.Time
	Authorizations   []AcmeAuthorization
	Certificate      []byte
	AttestedKey      []byte
	Error            string
}

func (o *AcmeOrder) UpdateOrder() {
	// the authorizations dont affect the order anymore, once it is being processed or is finished
	if o.Status == OrderStatusProcessing || o.Status == OrderStatusValid || o.Status == OrderStatusInvalid {
		return
	}

	validCount, invalidCount := 0, 0

	expired := time.Now().After(o.ExpiryTime)
	for i := range o.Authorizations {
		auth := &o.Authorizations[i]

		if expired &&
			auth.Status != AuthStatusInvalid &&
			auth.Status != AuthStatusDeactivated {
			auth.Status = AuthStatusExpired
			for j := range auth.Challenges {
				if auth.Challenges[j].Status == AuthStatusPending {
					auth.Challenges[j].Status = AuthStatusExpired
				}
			}
		}

		// authorization is valid if any of its challenges is valid
		if auth.Status != AuthStatusDeactivated && auth.Status != AuthStatusExpired {
			for j := range auth.Challenges {
				if auth.Challenges[j].Status == AuthStatusValid {
					auth.Status = AuthStatusValid
					break
				}
			}
		}

		if auth.Status == AuthStatusValid {
			validCount++
		} else if auth.Status != AuthStatusPending {
			invalidCount++
		}
	}

	// order is ready when all authorizations are valid
	if validCount == len(o.Authorizations) && o.Status == OrderStatusPending {
		o.Status = OrderStatusReady
	} else if invalidCount > 0 {
		o.Status = OrderStatusInvalid
	}
}

// identifier and tos-accepted can be read with out holding the mutex
// jwk and contacts and orders must be accessed while holding mux
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

func (a *AcmeAccount) TokenKeyAuthorization(token string) (string, error) {
	thumbprint, err := RawKeyThumbprint(a.Jwk)
	if err != nil {
		return "", fmt.Errorf("computing raw jwk thumbprint: %w", err)
	}
	return token + "." + base64.RawURLEncoding.EncodeToString(thumbprint), nil
}
func (a *AcmeAccount) TokenAccountCSR(token string, csrPubKeyDER []byte) ([]byte, error) {
	thumbprint, err := RawKeyThumbprint(a.Jwk)
	if err != nil {
		return nil, fmt.Errorf("computing raw jwk thumbprint: %w", err)
	}
	pubKeyHash := sha256.Sum256(csrPubKeyDER)
	keyAuth := token + "." + base64.RawURLEncoding.EncodeToString(thumbprint) + "." + base64.RawURLEncoding.EncodeToString(pubKeyHash[:])
	hash := sha256.Sum256([]byte(keyAuth))
	return hash[:], nil
}

type AcmeState struct {
	mux         sync.Mutex
	Nonce       AcmeNonceHandler
	accounts    map[string]*AcmeAccount
	Issuer      Issuer
	MetadataCas []*x509.Certificate
}

func NewAcmeState(issuer Issuer) *AcmeState {
	return &AcmeState{
		accounts: make(map[string]*AcmeAccount),
		Issuer:   issuer,
	}
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
