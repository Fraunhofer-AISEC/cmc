package main

import (
	"crypto/rand"
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
	for i := uint(0); i < AccountIdLength; i++ {
		identifier += string(dict[mrand.IntN(len(dict))])
	}
	return identifier
}

type AcmeStatus string

const (
	AcmeStatusPending     AcmeStatus = "pending"
	AcmeStatusReady       AcmeStatus = "ready"
	AcmeStatusValid       AcmeStatus = "valid"
	AcmeStatusExpired     AcmeStatus = "expired"
	AcmeStatusInvalid     AcmeStatus = "invalid"
	AcmeStatusDeactivated AcmeStatus = "deactivated"
)

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
	// expire pending and ready orders whose deadline has passed
	if time.Now().After(o.ExpiryTime) && (o.Status == AcmeStatusPending || o.Status == AcmeStatusReady) {
		o.Status = AcmeStatusInvalid
		for i := range o.Authorizations {
			if o.Authorizations[i].Status == AcmeStatusPending || o.Authorizations[i].Status == AcmeStatusValid {
				o.Authorizations[i].Status = AcmeStatusExpired
			}
		}
		return
	}

	if o.Status != AcmeStatusPending {
		return
	}

	validCount, incompleteCount := 0, 0
	for i := range o.Authorizations {
		switch o.Authorizations[i].Status {
		case AcmeStatusValid:
			validCount++
		case AcmeStatusPending:
			incompleteCount++
		}
	}

	if validCount == len(o.Authorizations) {
		o.Status = AcmeStatusReady
	} else if validCount+incompleteCount < len(o.Authorizations) {
		o.Status = AcmeStatusInvalid
	}
}

// AcmeAccount fields Identifier, Contacts, and TosAccepted are
// immutable after creation (set before the account is published to the
// shared map). They can be read without holding the mutex. The Jwk
// field may be updated by key rollover under both state.mux and
// account.mux; reads outside state.mux must hold account.mux. The
// Deactivated flag is accessed via atomic operations. The orders map
// must only be accessed while holding mux.
type AcmeAccount struct {
	mux         sync.Mutex
	Deactivated atomic.Bool
	Jwk         string
	Identifier  string
	Contacts    []string
	TosAccepted bool
	orders      map[string]*AcmeOrder
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
		Status:           AcmeStatusPending,
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
}

func NewAcmeState() *AcmeState {
	return &AcmeState{accounts: make(map[string]*AcmeAccount)}
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
