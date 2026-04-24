package main

import (
	"crypto/rand"
	mrand "math/rand/v2"
	"regexp"
	"sync"
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

	// allocate and add the next nonce
	next := &nonceListEntry{
		nonce: rand.Text(),
	}
	if n.list == nil {
		n.last, n.list, n.size = next, next, n.size+1
		return next.nonce
	}

	// check if the list needs to be shrunk
	n.last.next, n.last, n.size = next, next, n.size+1
	for ; n.size > NonceBufferSize; n.size = n.size - 1 {
		n.list = n.list.next
	}
	return next.nonce
}
func (n *AcmeNonceHandler) Check(nonce string) bool {
	n.mux.Lock()
	defer n.mux.Unlock()

	// find the nonce in the list and remove it
	for prev, next := (*nonceListEntry)(nil), n.list; next != nil; prev, next = next, next.next {
		if next.nonce != nonce {
			continue
		}

		// unlink the entry from the list
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

	// construct the new identifier
	for i := uint(0); i < AccountIdLength; i += 1 {
		identifier += string(dict[mrand.IntN(len(dict))])
	}
	return identifier
}

type AcmeStatus string

const (
	AcmeStatusPending AcmeStatus = "pending"
	AcmeStatusReady   AcmeStatus = "ready"
	AcmeStatusValid   AcmeStatus = "valid"
	AcmeStatusExpired AcmeStatus = "expired"
	AcmeStatusInvalid AcmeStatus = "invalid"
)

// maps a single challenge to each authorization
type AcmeAuthorization struct {
	Identifier    string
	Status        AcmeStatus
	Token         string
	ChallengeType string
	Validated     string
}

type AcmeOrder struct {
	Identifier       string
	Status           AcmeStatus
	RequestNotBefore string
	RequestNotAfter  string
	ExpiryTime       time.Time
	Authorizations   []AcmeAuthorization
}

func (o *AcmeOrder) UpdateOrder() {
	now, validCount, incompleteCount := time.Now(), 0, 0
	if o.Status != AcmeStatusPending {
		return
	}

	// patch the status according to the authorizations
	for _, auth := range o.Authorizations {
		if now.After(o.ExpiryTime) {
			auth.Status = AcmeStatusExpired
		} else if auth.Status == AcmeStatusValid {
			validCount += 1
		} else if auth.Status == AcmeStatusPending {
			incompleteCount += 1
		}
	}

	// patch the overall status
	if validCount == len(o.Authorizations) {
		o.Status = AcmeStatusReady
	} else if validCount+incompleteCount < len(o.Authorizations) {
		o.Status = AcmeStatusInvalid
	}
}

type AcmeAccount struct {
	mux         sync.Mutex
	Jwk         string
	Identifier  string
	Contacts    []string
	Orders      map[string]*AcmeOrder
	TosAccepted bool
}

func (a *AcmeAccount) NewOrder() *AcmeOrder {
	a.mux.Lock()
	defer a.mux.Unlock()

	for {
		identifier := makeNewIdentifier()
		if _, ok := a.Orders[identifier]; ok {
			continue
		}

		// allocate and assign the new order
		order := &AcmeOrder{Identifier: identifier}
		a.Orders[identifier] = order
		return order
	}
}
func (a *AcmeAccount) LookupOrderById(id string) *AcmeOrder {
	a.mux.Lock()
	defer a.mux.Unlock()

	order, ok := a.Orders[id]
	if !ok {
		return nil
	}
	return order
}

type AcmeState struct {
	mux      sync.Mutex
	Nonce    AcmeNonceHandler
	accounts map[string]*AcmeAccount
}

func NewAcmeState() *AcmeState {
	return &AcmeState{accounts: make(map[string]*AcmeAccount)}
}
func (s *AcmeState) LookupAccountByKey(jwk string) *AcmeAccount {
	s.mux.Lock()
	defer s.mux.Unlock()

	// TODO: better comparison, as jwk may not be same serialized string
	for _, acc := range s.accounts {
		if acc.Jwk == jwk {
			return acc
		}
	}
	return nil
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
func (s *AcmeState) NewAccount() *AcmeAccount {
	s.mux.Lock()
	defer s.mux.Unlock()

	for {
		identifier := makeNewIdentifier()
		if _, ok := s.accounts[identifier]; ok {
			continue
		}

		// allocate and assign the new entry
		account := &AcmeAccount{Identifier: identifier, Orders: make(map[string]*AcmeOrder)}
		s.accounts[identifier] = account
		return account
	}
}
