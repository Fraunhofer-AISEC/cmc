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
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	AcmeErrAccountDoesNotExist   = "urn:ietf:params:acme:error:accountDoesNotExist"
	AcmeErrBadNonce              = "urn:ietf:params:acme:error:badNonce"
	AcmeErrMalformed             = "urn:ietf:params:acme:error:malformed"
	AcmeErrOrderNotReady         = "urn:ietf:params:acme:error:orderNotReady"
	AcmeErrUnauthorized          = "urn:ietf:params:acme:error:unauthorized"
	AcmeErrUnsupportedIdentifier = "urn:ietf:params:acme:error:unsupportedIdentifier"
	AcmeErrServerInternal        = "urn:ietf:params:acme:error:serverInternal"
)

func acmeError(resp http.ResponseWriter, status int, errType string, detail string) {
	resp.Header().Set("Content-Type", "application/problem+json; charset=utf-8")
	resp.WriteHeader(status)
	json.NewEncoder(resp).Encode(map[string]any{
		"type":   errType,
		"detail": detail,
		"status": status,
	})
}

func handleAcmeDispatch(state *AcmeState, req *http.Request, resp http.ResponseWriter, https bool) {
	url := &url.URL{
		Scheme: (func(https bool) string {
			if https {
				return "https"
			}
			return "http"
		})(https),
		Host:        req.Host,
		Path:        req.URL.Path,
		RawPath:     req.URL.RawPath,
		RawQuery:    req.URL.RawQuery,
		Fragment:    req.URL.Fragment,
		RawFragment: req.URL.RawFragment,
	}

	switch {
	case url.Path == "/":
		handleDirectory(url, req, resp)
	case url.Path == "/nonce":
		handleNewNonce(state, url, req, resp)
	case url.Path == "/new-account":
		handleNewAccount(state, url, req, resp)
	case url.Path == "/new-order":
		handleNewOrder(state, url, req, resp)
	case url.Path == "/tos":
		handleTermsOfService(url, req, resp)
	case url.Path == "/ca":
		handleCA(state, url, req, resp)
	case url.Path == "/key-change":
		handleKeyChange(state, url, req, resp)
	case strings.HasPrefix(url.Path, "/account/"):
		handleAccount(state, url, req, resp)
	case strings.HasPrefix(url.Path, "/orders/"):
		handleOrders(state, url, req, resp)
	case strings.HasPrefix(url.Path, "/order/"):
		handleOrder(state, url, req, resp)
	case strings.HasPrefix(url.Path, "/auth/"):
		handleAuth(state, url, req, resp)
	case strings.HasPrefix(url.Path, "/certificate/"):
		handleCertificate(state, url, req, resp)
	case strings.HasPrefix(url.Path, "/finalize/"):
		handleFinalize(state, url, req, resp)
	case strings.HasPrefix(url.Path, "/challenge/"):
		handleChallenge(state, url, req, resp)
	default:
		handleNotFound(url, resp)
	}
}

func makeFullURL(url *url.URL, path string) string {
	base := ""
	if url.Scheme != "" {
		base += url.Scheme + "://"
	}
	base += url.Host

	relative := path[:]
	if len(relative) > 0 && strings.HasPrefix(relative, "/") {
		relative = relative[1:]
	}

	return fmt.Sprintf("%v/%v", base, relative)
}
func setLinkDirectory(url *url.URL, resp http.ResponseWriter) {
	resp.Header().Set("Link", fmt.Sprintf("<%v>; rel=\"index\"", makeFullURL(url, "/")))
}
func setReplayNonce(state *AcmeState, resp http.ResponseWriter) {
	resp.Header().Set("Cache-Control", "no-store")
	resp.Header().Set("Replay-Nonce", state.Nonce.AllocNext())
}
func respondWithJson(status int, resp http.ResponseWriter, value any) {
	resp.Header().Set("Content-Type", "application/json; charset=utf-8")
	resp.WriteHeader(status)
	json.NewEncoder(resp).Encode(value)
}
func authenticateRequest(state *AcmeState, url *url.URL, req *http.Request, resp http.ResponseWriter) ([]byte, *AcmeAccount) {
	if req.Method != http.MethodPost {
		resp.Header().Add("Allow", http.MethodPost)
		resp.WriteHeader(http.StatusMethodNotAllowed)
		return nil, nil
	}
	setLinkDirectory(url, resp)
	setReplayNonce(state, resp)

	jwsBody := UnpackAndParseJWS(url, req, resp)
	if jwsBody == nil {
		return nil, nil
	}

	if !state.Nonce.Check(jwsBody.Nonce) {
		acmeError(resp, http.StatusBadRequest, AcmeErrBadNonce, "outdated or invalid nonce")
		return nil, nil
	}

	var account *AcmeAccount
	if index := strings.Index(jwsBody.Kid, "/account/"); index == -1 {
		acmeError(resp, http.StatusBadRequest, AcmeErrAccountDoesNotExist, "unknown account kid")
		return nil, nil
	} else if account = state.LookupAccountById(jwsBody.Kid[index+9:]); account == nil {
		acmeError(resp, http.StatusBadRequest, AcmeErrAccountDoesNotExist, "unknown account kid")
		return nil, nil
	} else if account.Deactivated.Load() {
		acmeError(resp, http.StatusForbidden, AcmeErrUnauthorized, "account is deactivated")
		return nil, nil
	}

	account.mux.Lock()
	jwk := account.Jwk
	account.mux.Unlock()
	if !ValidateJWSWithJWK(jwsBody, resp, jwk) {
		return nil, nil
	}
	return jwsBody.Payload, account
}
func sendAccountResource(status int, account *AcmeAccount, url *url.URL, resp http.ResponseWriter) {
	accountStatus := AccountStatusValid
	if account.Deactivated.Load() {
		accountStatus = AccountStatusDeactivated
	}
	resp.Header().Set("Location", makeFullURL(url, fmt.Sprintf("/account/%v", account.Identifier)))
	respondWithJson(status, resp, map[string]any{
		"status":  string(accountStatus),
		"contact": account.GetContacts(),
		"orders":  makeFullURL(url, "/orders"),
	})
}
func sendOrderResource(status int, order *AcmeOrder, url *url.URL, resp http.ResponseWriter) {
	type OrderIdentifier struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	}

	taskList := []string{}
	idList := []OrderIdentifier{}
	for i, auth := range order.Authorizations {
		taskList = append(taskList, makeFullURL(url, fmt.Sprintf("/auth/%v/%v", order.Identifier, i)))
		idList = append(idList, OrderIdentifier{Type: "dns", Value: auth.Identifier})
	}

	result := map[string]any{
		"status":         string(order.Status),
		"expires":        order.ExpiryTime.Format(time.RFC3339Nano),
		"notBefore":      time.Now(),
		"notAfter":       time.Now().Add(OrderLifeTime),
		"identifiers":    idList,
		"authorizations": taskList,
		"finalize":       makeFullURL(url, fmt.Sprintf("/finalize/%v", order.Identifier)),
	}
	if order.Certificate != nil {
		result["certificate"] = makeFullURL(url, fmt.Sprintf("/certificate/%v", order.Identifier))
	}

	resp.Header().Set("Location", makeFullURL(url, fmt.Sprintf("/order/%v", order.Identifier)))
	respondWithJson(status, resp, result)
}

func handleNotFound(url *url.URL, resp http.ResponseWriter) {
	setLinkDirectory(url, resp)
	acmeError(resp, http.StatusNotFound, AcmeErrMalformed, "unknown resource on this ACME server")
}
func handleDirectory(url *url.URL, req *http.Request, resp http.ResponseWriter) {
	if req.Method != http.MethodGet {
		resp.Header().Add("Allow", http.MethodGet)
		resp.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	respondWithJson(http.StatusOK, resp, map[string]any{
		"newNonce":   makeFullURL(url, "/nonce"),
		"newAccount": makeFullURL(url, "/new-account"),
		"newOrder":   makeFullURL(url, "/new-order"),
		"keyChange":  makeFullURL(url, "/key-change"),
		"meta": map[string]any{
			"termsOfService":          makeFullURL(url, "/tos"),
			"caaIdentities":           []string{"test.com"},
			"externalAccountRequired": false,
			"caCertificate":           makeFullURL(url, "/ca"),
		},
	})
}
func handleTermsOfService(url *url.URL, req *http.Request, resp http.ResponseWriter) {
	if req.Method != http.MethodGet {
		resp.Header().Add("Allow", http.MethodGet)
		resp.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	setLinkDirectory(url, resp)
	resp.Header().Set("Content-Type", "text/plain; charset=utf-8")
	resp.WriteHeader(http.StatusOK)
	resp.Write([]byte("Be friendly! :)\n"))
}
func handleCA(state *AcmeState, url *url.URL, req *http.Request, resp http.ResponseWriter) {
	if req.Method != http.MethodGet {
		resp.Header().Add("Allow", http.MethodGet)
		resp.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	setLinkDirectory(url, resp)
	resp.Header().Set("Content-Type", "application/pem-certificate-chain")
	resp.WriteHeader(http.StatusOK)
	resp.Write(state.CACert)
}
func handleNewNonce(state *AcmeState, url *url.URL, req *http.Request, resp http.ResponseWriter) {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		resp.Header().Add("Allow", http.MethodGet)
		resp.Header().Add("Allow", http.MethodHead)
		resp.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	setLinkDirectory(url, resp)
	setReplayNonce(state, resp)

	if req.Method == http.MethodGet {
		resp.WriteHeader(http.StatusNoContent)
	} else {
		resp.WriteHeader(http.StatusOK)
	}
}
func handleNewAccount(state *AcmeState, url *url.URL, req *http.Request, resp http.ResponseWriter) {
	if req.Method != http.MethodPost {
		resp.Header().Add("Allow", http.MethodPost)
		resp.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	setLinkDirectory(url, resp)
	setReplayNonce(state, resp)

	jwsBody := UnpackAndParseJWS(url, req, resp)
	if jwsBody == nil {
		return
	}

	if !state.Nonce.Check(jwsBody.Nonce) {
		acmeError(resp, http.StatusBadRequest, AcmeErrBadNonce, "outdated or invalid nonce")
		return
	}

	if !ValidateJWSWithJWK(jwsBody, resp, jwsBody.Key) {
		return
	}

	// parse and validate the payload before any state mutations
	payload := struct {
		OnlyReturnExisting     bool     `json:"onlyReturnExisting"`
		Contacts               []string `json:"contact"`
		ExternalAccountBinding any      `json:"externalAccountBinding,omitempty"`
		TermsOfServiceAgreed   bool     `json:"termsOfServiceAgreed"`
	}{}
	if err := json.Unmarshal(jwsBody.Payload, &payload); err != nil {
		acmeError(resp, http.StatusBadRequest, AcmeErrMalformed, "malformed account creation payload")
		return
	}

	if payload.OnlyReturnExisting {
		account := state.LookupAccountByKey(jwsBody.Key)
		if account == nil {
			acmeError(resp, http.StatusBadRequest, AcmeErrAccountDoesNotExist, "account does not exist")
			return
		}
		sendAccountResource(http.StatusOK, account, url, resp)
		return
	}

	for _, contact := range payload.Contacts {
		if !ValidateContact(contact) {
			acmeError(resp, http.StatusBadRequest, AcmeErrMalformed, fmt.Sprintf("malformed contact [%v] encountered", contact))
			return
		}
	}
	if !payload.TermsOfServiceAgreed {
		acmeError(resp, http.StatusBadRequest, AcmeErrMalformed, "terms of service have not been agreed to")
		return
	}
	if payload.ExternalAccountBinding != nil {
		acmeError(resp, http.StatusBadRequest, AcmeErrMalformed, "external account bindings not required")
		return
	}

	account, created := state.FindOrCreateAccount(jwsBody.Key, payload.Contacts, payload.TermsOfServiceAgreed)
	if created {
		sendAccountResource(http.StatusCreated, account, url, resp)
	} else {
		sendAccountResource(http.StatusOK, account, url, resp)
	}
}
func handleNewOrder(state *AcmeState, url *url.URL, req *http.Request, resp http.ResponseWriter) {
	rawPayload, account := authenticateRequest(state, url, req, resp)
	if rawPayload == nil {
		return
	}

	type OrderIdentifier struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	}
	payload := struct {
		Identifier []OrderIdentifier `json:"identifiers"`
		NotBefore  string            `json:"notBefore"`
		NotAfter   string            `json:"notAfter"`
	}{}
	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		acmeError(resp, http.StatusBadRequest, AcmeErrMalformed, "malformed order creation payload")
		return
	}

	if len(payload.Identifier) == 0 {
		acmeError(resp, http.StatusBadRequest, AcmeErrMalformed, "cannot create order for empty identifiers")
		return
	}
	for _, ident := range payload.Identifier {
		if ident.Type != "dns" {
			acmeError(resp, http.StatusBadRequest, AcmeErrUnsupportedIdentifier, "server only supports dns identifier")
			return
		}
		if !ValidateIdentifier(ident.Value) {
			acmeError(resp, http.StatusBadRequest, AcmeErrMalformed, "malformed dns identifier")
			return
		}
	}

	var notBefore, notAfter *time.Time
	if len(payload.NotBefore) > 0 {
		if time, err := time.Parse(time.RFC3339Nano, payload.NotBefore); err != nil {
			acmeError(resp, http.StatusBadRequest, AcmeErrMalformed, "invalid before time format")
			return
		} else {
			notBefore = &time
		}
	}
	if len(payload.NotAfter) > 0 {
		if time, err := time.Parse(time.RFC3339Nano, payload.NotAfter); err != nil {
			acmeError(resp, http.StatusBadRequest, AcmeErrMalformed, "invalid after time format")
			return
		} else {
			notAfter = &time
		}
	}
	if notBefore != nil && notAfter != nil && !notBefore.Before(*notAfter) {
		acmeError(resp, http.StatusBadRequest, AcmeErrMalformed, "invalid order in time constraints")
		return
	}

	auths := make([]AcmeAuthorization, 0, len(payload.Identifier))
	for _, ident := range payload.Identifier {
		auths = append(auths, AcmeAuthorization{
			Identifier:    ident.Value,
			Status:        AuthStatusPending,
			Token:         rand.Text(),
			ChallengeType: "http-01",
		})
	}

	order := account.CreateOrder(auths, payload.NotBefore, payload.NotAfter, time.Now().Add(OrderTimeWindow))
	sendOrderResource(http.StatusCreated, order, url, resp)
}
func handleAccount(state *AcmeState, url *url.URL, req *http.Request, resp http.ResponseWriter) {
	rawPayload, account := authenticateRequest(state, url, req, resp)
	if rawPayload == nil {
		return
	}

	// empty payload returns account info
	if len(rawPayload) == 0 {
		sendAccountResource(http.StatusOK, account, url, resp)
		return
	}

	// parse account update
	payload := struct {
		Status   string   `json:"status"`
		Contacts []string `json:"contact"`
	}{}
	if err := json.Unmarshal(rawPayload, &payload); err != nil {
		acmeError(resp, http.StatusBadRequest, AcmeErrMalformed, "malformed account update payload")
		return
	}

	if payload.Status == string(AccountStatusDeactivated) {
		account.Deactivated.Store(true)
		sendAccountResource(http.StatusOK, account, url, resp)
		return
	}

	if payload.Contacts != nil {
		for _, contact := range payload.Contacts {
			if !ValidateContact(contact) {
				acmeError(resp, http.StatusBadRequest, AcmeErrMalformed, fmt.Sprintf("malformed contact [%v] encountered", contact))
				return
			}
		}
		account.UpdateContacts(payload.Contacts)
		sendAccountResource(http.StatusOK, account, url, resp)
		return
	}

	acmeError(resp, http.StatusBadRequest, AcmeErrMalformed, "unsupported account update")
}
func handleKeyChange(state *AcmeState, url *url.URL, req *http.Request, resp http.ResponseWriter) {
	rawPayload, account := authenticateRequest(state, url, req, resp)
	if rawPayload == nil {
		return
	}

	inner := ParseJWS(rawPayload, url, resp, "inner JWS")
	if inner == nil {
		return
	}
	if inner.Key == "" {
		acmeError(resp, http.StatusBadRequest, AcmeErrMalformed, "inner JWS must contain a JWK")
		return
	}
	if !ValidateJWSWithJWK(inner, resp, inner.Key) {
		return
	}

	var keyChangePayload struct {
		Account string `json:"account"`
		OldKey  any    `json:"oldKey"`
	}
	if err := json.Unmarshal(inner.Payload, &keyChangePayload); err != nil {
		acmeError(resp, http.StatusBadRequest, AcmeErrMalformed, "malformed key change payload")
		return
	}

	if !strings.HasSuffix(keyChangePayload.Account, "/account/"+account.Identifier) {
		acmeError(resp, http.StatusBadRequest, AcmeErrMalformed, "account URL mismatch in key change")
		return
	}

	oldKeyCanonical, err := CanonicalJSON(keyChangePayload.OldKey)
	if err != nil {
		acmeError(resp, http.StatusBadRequest, AcmeErrMalformed, "malformed old key in key change")
		return
	}

	conflict := state.ChangeAccountKey(account, oldKeyCanonical, inner.Key)
	if conflict == account {
		acmeError(resp, http.StatusBadRequest, AcmeErrMalformed, "old key does not match account key")
		return
	}
	if conflict != nil {
		resp.Header().Set("Location", makeFullURL(url, fmt.Sprintf("/account/%v", conflict.Identifier)))
		acmeError(resp, http.StatusConflict, AcmeErrMalformed, "new key already in use by another account")
		return
	}

	sendAccountResource(http.StatusOK, account, url, resp)
}
func handleOrders(state *AcmeState, url *url.URL, req *http.Request, resp http.ResponseWriter) {
	rawPayload, account := authenticateRequest(state, url, req, resp)
	if rawPayload == nil {
		return
	}
	if len(rawPayload) != 0 {
		acmeError(resp, http.StatusBadRequest, AcmeErrMalformed, "malformed request payload")
		return
	}

	ids := account.OrderIDs()
	orders := make([]string, 0, len(ids))
	for _, id := range ids {
		orders = append(orders, makeFullURL(url, fmt.Sprintf("/order/%v", id)))
	}

	respondWithJson(http.StatusOK, resp, map[string]any{
		"orders": orders,
	})
}
func handleOrder(state *AcmeState, url *url.URL, req *http.Request, resp http.ResponseWriter) {
	var orderIdentifier string
	if index := strings.Index(url.Path, "/order/"); index == -1 {
		acmeError(resp, http.StatusNotFound, AcmeErrMalformed, "malformed order identifier")
		return
	} else {
		orderIdentifier = url.Path[index+7:]
	}

	rawPayload, account := authenticateRequest(state, url, req, resp)
	if rawPayload == nil {
		return
	}
	if len(rawPayload) != 0 {
		acmeError(resp, http.StatusBadRequest, AcmeErrMalformed, "malformed request payload")
		return
	}

	account.mux.Lock()
	defer account.mux.Unlock()

	order := account.orders[orderIdentifier]
	if order == nil {
		acmeError(resp, http.StatusNotFound, AcmeErrMalformed, "unknown order identifier")
		return
	}
	order.UpdateOrder()
	sendOrderResource(http.StatusOK, order, url, resp)
}
func handleAuth(state *AcmeState, url *url.URL, req *http.Request, resp http.ResponseWriter) {
	var orderIdentifier string
	var idIndex int
	if indexId := strings.Index(url.Path, "/auth/"); indexId == -1 {
		acmeError(resp, http.StatusNotFound, AcmeErrMalformed, "malformed authorization identifier")
		return
	} else if indexIndex := strings.Index(url.Path[indexId+6:], "/"); indexIndex == -1 {
		acmeError(resp, http.StatusNotFound, AcmeErrMalformed, "malformed authorization identifier")
		return
	} else {
		indexIndex += indexId + 6
		orderIdentifier = url.Path[indexId+6 : indexIndex]
		var err error
		if idIndex, err = strconv.Atoi(url.Path[indexIndex+1:]); err != nil {
			acmeError(resp, http.StatusNotFound, AcmeErrMalformed, "malformed authorization identifier")
			return
		}
	}

	rawPayload, account := authenticateRequest(state, url, req, resp)
	if rawPayload == nil {
		return
	}

	account.mux.Lock()
	defer account.mux.Unlock()

	order := account.orders[orderIdentifier]
	if order == nil {
		acmeError(resp, http.StatusNotFound, AcmeErrMalformed, "unknown order identifier")
		return
	}
	order.UpdateOrder()

	if idIndex >= len(order.Authorizations) {
		acmeError(resp, http.StatusNotFound, AcmeErrMalformed, "unknown authorization identifier")
		return
	}
	auth := &order.Authorizations[idIndex]

	if len(rawPayload) != 0 {
		payload := struct {
			Status string `json:"status"`
		}{}
		if err := json.Unmarshal(rawPayload, &payload); err != nil || payload.Status != string(AuthStatusDeactivated) {
			acmeError(resp, http.StatusBadRequest, AcmeErrMalformed, "malformed authorization update payload")
			return
		}
		if auth.Status != AuthStatusPending && auth.Status != AuthStatusValid {
			acmeError(resp, http.StatusBadRequest, AcmeErrMalformed, "cannot deactivate authorization in current state")
			return
		}
		auth.Status = AuthStatusDeactivated
		order.UpdateOrder()
	}

	respondWithJson(http.StatusOK, resp, map[string]any{
		"status":  string(auth.Status),
		"expires": order.ExpiryTime.Format(time.RFC3339Nano),
		"identifier": map[string]string{
			"type":  "dns",
			"value": auth.Identifier,
		},
		"challenges": []any{map[string]string{
			"type":      auth.ChallengeType,
			"url":       makeFullURL(url, fmt.Sprintf("/challenge/%v/%v", orderIdentifier, idIndex)),
			"status":    string(auth.Status),
			"token":     auth.Token,
			"validated": auth.Validated,
		}},
	})
}
func handleChallenge(state *AcmeState, url *url.URL, req *http.Request, resp http.ResponseWriter) {
	var orderIdentifier string
	var idIndex int
	if indexId := strings.Index(url.Path, "/challenge/"); indexId == -1 {
		acmeError(resp, http.StatusNotFound, AcmeErrMalformed, "malformed challenge identifier")
		return
	} else if indexIndex := strings.Index(url.Path[indexId+11:], "/"); indexIndex == -1 {
		acmeError(resp, http.StatusNotFound, AcmeErrMalformed, "malformed challenge identifier")
		return
	} else {
		indexIndex += indexId + 11
		orderIdentifier = url.Path[indexId+11 : indexIndex]
		var err error
		if idIndex, err = strconv.Atoi(url.Path[indexIndex+1:]); err != nil {
			acmeError(resp, http.StatusNotFound, AcmeErrMalformed, "malformed challenge identifier")
			return
		}
	}

	rawPayload, account := authenticateRequest(state, url, req, resp)
	if rawPayload == nil {
		return
	}
	if !bytes.Equal(rawPayload, []byte("{}")) {
		acmeError(resp, http.StatusBadRequest, AcmeErrMalformed, "malformed request payload")
		return
	}

	account.mux.Lock()
	defer account.mux.Unlock()

	order := account.orders[orderIdentifier]
	if order == nil {
		acmeError(resp, http.StatusNotFound, AcmeErrMalformed, "unknown order identifier")
		return
	}
	order.UpdateOrder()

	if idIndex >= len(order.Authorizations) {
		acmeError(resp, http.StatusNotFound, AcmeErrMalformed, "unknown authorization identifier")
		return
	}
	auth := &order.Authorizations[idIndex]

	if auth.Status == AuthStatusPending {
		// TODO: implement actual challenge validation/verification
		auth.Status = AuthStatusValid
		auth.Validated = time.Now().Format(time.RFC3339Nano)
	}

	respondWithJson(http.StatusOK, resp, map[string]any{
		"type":      auth.ChallengeType,
		"url":       makeFullURL(url, fmt.Sprintf("/challenge/%v/%v", orderIdentifier, idIndex)),
		"status":    string(auth.Status),
		"token":     auth.Token,
		"validated": auth.Validated,
	})
}
func handleCertificate(state *AcmeState, url *url.URL, req *http.Request, resp http.ResponseWriter) {
	var orderIdentifier string
	if index := strings.Index(url.Path, "/certificate/"); index == -1 {
		acmeError(resp, http.StatusNotFound, AcmeErrMalformed, "malformed certificate identifier")
		return
	} else {
		orderIdentifier = url.Path[index+13:]
	}

	rawPayload, account := authenticateRequest(state, url, req, resp)
	if rawPayload == nil {
		return
	}
	if len(rawPayload) != 0 {
		acmeError(resp, http.StatusBadRequest, AcmeErrMalformed, "malformed request payload")
		return
	}

	account.mux.Lock()
	order := account.orders[orderIdentifier]
	if order == nil {
		account.mux.Unlock()
		acmeError(resp, http.StatusNotFound, AcmeErrMalformed, "unknown order identifier")
		return
	}
	cert := order.Certificate
	account.mux.Unlock()

	if cert == nil {
		acmeError(resp, http.StatusNotFound, AcmeErrMalformed, "certificate not yet issued")
		return
	}

	resp.Header().Set("Content-Type", "application/pem-certificate-chain")
	resp.WriteHeader(http.StatusOK)
	resp.Write(cert)
}
func handleFinalize(state *AcmeState, url *url.URL, req *http.Request, resp http.ResponseWriter) {
	var orderIdentifier string
	if index := strings.Index(url.Path, "/finalize/"); index == -1 {
		acmeError(resp, http.StatusNotFound, AcmeErrMalformed, "malformed finalize identifier")
		return
	} else {
		orderIdentifier = url.Path[index+10:]
	}

	rawPayload, account := authenticateRequest(state, url, req, resp)
	if rawPayload == nil {
		return
	}

	account.mux.Lock()
	defer account.mux.Unlock()

	order := account.orders[orderIdentifier]
	if order == nil {
		acmeError(resp, http.StatusNotFound, AcmeErrMalformed, "unknown order identifier")
		return
	}
	order.UpdateOrder()

	if order.Status != OrderStatusReady {
		acmeError(resp, http.StatusForbidden, AcmeErrOrderNotReady, "order is not ready for finalization")
		return
	}

	payload := struct {
		CSR string `json:"csr"`
	}{}
	if err := json.Unmarshal(rawPayload, &payload); err != nil || payload.CSR == "" {
		acmeError(resp, http.StatusBadRequest, AcmeErrMalformed, "malformed finalize payload")
		return
	}

	csrDER, err := base64.RawURLEncoding.DecodeString(payload.CSR)
	if err != nil {
		acmeError(resp, http.StatusBadRequest, AcmeErrMalformed, "malformed CSR encoding")
		return
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		acmeError(resp, http.StatusBadRequest, AcmeErrMalformed, "malformed CSR")
		return
	}
	if err := csr.CheckSignature(); err != nil {
		acmeError(resp, http.StatusBadRequest, AcmeErrMalformed, "invalid CSR signature")
		return
	}

	orderDNS := make([]string, 0, len(order.Authorizations))
	for _, auth := range order.Authorizations {
		orderDNS = append(orderDNS, auth.Identifier)
	}
	sort.Strings(orderDNS)

	csrDNS := make([]string, len(csr.DNSNames))
	copy(csrDNS, csr.DNSNames)
	sort.Strings(csrDNS)

	if !slices.Equal(orderDNS, csrDNS) {
		acmeError(resp, http.StatusBadRequest, AcmeErrMalformed, "CSR identifiers do not match order identifiers")
		return
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		acmeError(resp, http.StatusInternalServerError, AcmeErrServerInternal, "failed to generate serial number")
		return
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(OrderLifeTime)
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{CommonName: csr.DNSNames[0]},
		DNSNames:     csr.DNSNames,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, state.CAx509, csr.PublicKey, state.CAKey)
	if err != nil {
		acmeError(resp, http.StatusInternalServerError, AcmeErrServerInternal, "failed to sign certificate")
		return
	}

	var chain bytes.Buffer
	pem.Encode(&chain, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	pem.Encode(&chain, &pem.Block{Type: "CERTIFICATE", Bytes: state.CAx509.Raw})

	order.Certificate = chain.Bytes()
	order.Status = OrderStatusValid

	sendOrderResource(http.StatusOK, order, url, resp)
}
