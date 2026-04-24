package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

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
	case strings.HasPrefix(url.Path, "/account/"):
		handleAccount(state, url, req, resp)
	case strings.HasPrefix(url.Path, "/orders/"):
		handleOrders(state, url, req, resp)
	case strings.HasPrefix(url.Path, "/order/"):
		handleOrder(state, url, req, resp)
	case strings.HasPrefix(url.Path, "/auth/"):
		handleAuth(state, url, req, resp)
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
	enc := json.NewEncoder(resp)
	enc.Encode(value)
}
func processPostAsGet(state *AcmeState, url *url.URL, req *http.Request, resp http.ResponseWriter) ([]byte, *AcmeAccount) {
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

	// validate the nonce
	if !state.Nonce.Check(jwsBody.Nonce) {
		http.Error(resp, "outdated or invalid nonce", http.StatusBadRequest)
		return nil, nil
	}

	// check if the account exists
	var account *AcmeAccount
	if index := strings.Index(jwsBody.Kid, "/account/"); index == -1 {
		http.Error(resp, "unknown account kid", http.StatusBadRequest)
		return nil, nil
	} else if account = state.LookupAccountById(jwsBody.Kid[index+9:]); account == nil {
		http.Error(resp, "unknown account kid", http.StatusBadRequest)
		return nil, nil
	}

	// validate the signature itself (based on the account key)
	if !ValidateJWSWithJWK(jwsBody, resp, account.Jwk) {
		return nil, nil
	}
	return jwsBody.Payload, account
}
func sendAccountResource(status int, account *AcmeAccount, url *url.URL, resp http.ResponseWriter) {
	resp.Header().Set("Location", makeFullURL(url, fmt.Sprintf("/account/%v", account.Identifier)))
	respondWithJson(status, resp, map[string]any{
		"status":  "valid",
		"contact": account.Contacts,
		"orders":  makeFullURL(url, "/orders"),
	})
}
func sendOrderResource(status int, order *AcmeOrder, url *url.URL, resp http.ResponseWriter) {
	type OrderIdentifier struct {
		Type  string `json:"type"`
		Value string `json:"value"`
	}

	// setup the list of tasks and ids
	taskList := []string{}
	idList := []OrderIdentifier{}
	for i, auth := range order.Authorizations {
		taskList = append(taskList, makeFullURL(url, fmt.Sprintf("/auth/%v/%v", order.Identifier, i)))
		idList = append(idList, OrderIdentifier{Type: "dns", Value: auth.Identifier})
	}

	// return the created order
	resp.Header().Set("Location", makeFullURL(url, fmt.Sprintf("/order/%v", order.Identifier)))
	respondWithJson(status, resp, map[string]any{
		"status":         string(order.Status),
		"expires":        order.ExpiryTime.Format(time.RFC3339Nano),
		"notBefore":      time.Now(),
		"notAfter":       time.Now().Add(OrderLifeTime),
		"identifiers":    idList,
		"authorizations": taskList,
		"finalize":       makeFullURL(url, fmt.Sprintf("/finalize/%v", order.Identifier)),
	})
}

func handleNotFound(url *url.URL, resp http.ResponseWriter) {
	setLinkDirectory(url, resp)
	resp.Header().Set("Content-Type", "text/plain; charset=utf-8")
	resp.WriteHeader(http.StatusNotFound)
	resp.Write([]byte("Unknown resource on this ACME server\n"))
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
		"meta": map[string]any{
			"termsOfService":          makeFullURL(url, "/tos"),
			"caaIdentities":           []string{"test.com"},
			"externalAccountRequired": false,
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

	// validate the nonce
	if !state.Nonce.Check(jwsBody.Nonce) {
		http.Error(resp, "outdated or invalid nonce", http.StatusBadRequest)
		return
	}

	// validate the signature itself (based on the key provided in the header)
	if !ValidateJWSWithJWK(jwsBody, resp, jwsBody.Key) {
		return
	}

	// check if the account already exists
	account, created := state.LookupAccountByKey(jwsBody.Key), false
	if account == nil {
		created = true

		// parse the payload
		payload := struct {
			OnlyReturnExisting     bool     `json:"onlyReturnExisting"`
			Contacts               []string `json:"contact"`
			ExternalAccountBinding any      `json:"externalAccountBinding,omitempty"`
			TermsOfServiceAgreed   bool     `json:"termsOfServiceAgreed"`
		}{}
		if err := json.Unmarshal(jwsBody.Payload, &payload); err != nil {
			http.Error(resp, "malformed account creation payload", http.StatusBadRequest)
			return
		}

		// check if the existance of an account is checked
		if payload.OnlyReturnExisting {
			http.Error(resp, "account does not exist", http.StatusBadRequest)
			return
		}

		// validate the contacts
		for _, contact := range payload.Contacts {
			if !ValidateContact(contact) {
				http.Error(resp, fmt.Sprintf("malformed contact [%v] encountered", contact), http.StatusBadRequest)
				return
			}
		}

		// validate the tos flags
		if !payload.TermsOfServiceAgreed {
			http.Error(resp, "terms of service have not been agreed to", http.StatusBadRequest)
			return
		}

		// no external account bindings supported
		if payload.ExternalAccountBinding != nil {
			http.Error(resp, "external account bindings not required", http.StatusBadRequest)
			return
		}

		// allocate the new account and populate it
		account = state.NewAccount()
		account.mux.Lock()
		account.Jwk = jwsBody.Key
		account.Contacts = payload.Contacts
		account.TosAccepted = true
	} else {
		account.mux.Lock()
	}
	defer account.mux.Unlock()

	// return the created/found account
	if created {
		sendAccountResource(http.StatusCreated, account, url, resp)
	} else {
		sendAccountResource(http.StatusOK, account, url, resp)
	}
}
func handleNewOrder(state *AcmeState, url *url.URL, req *http.Request, resp http.ResponseWriter) {
	// resolve the account and payload and validate them
	rawPayload, account := processPostAsGet(state, url, req, resp)
	if rawPayload == nil {
		return
	}

	// parse the payload
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
		http.Error(resp, "malformed order creation payload", http.StatusBadRequest)
		return
	}

	// validate the identifier
	if len(payload.Identifier) == 0 {
		http.Error(resp, "cannot create order for empty identifiers", http.StatusBadRequest)
		return
	}
	for _, ident := range payload.Identifier {
		if ident.Type != "dns" {
			http.Error(resp, "server only supports dns identifier", http.StatusBadRequest)
			return
		}
		if !ValidateIdentifier(ident.Value) {
			http.Error(resp, "malformed dns identifier", http.StatusBadRequest)
			return
		}
	}

	// validate the times
	var notBefore, notAfter *time.Time
	if len(payload.NotBefore) > 0 {
		if time, err := time.Parse(time.RFC3339Nano, payload.NotBefore); err != nil {
			http.Error(resp, "invalid before time format", http.StatusBadRequest)
			return
		} else {
			notBefore = &time
		}
	}
	if len(payload.NotAfter) > 0 {
		if time, err := time.Parse(time.RFC3339Nano, payload.NotAfter); err != nil {
			http.Error(resp, "invalid after time format", http.StatusBadRequest)
			return
		} else {
			notAfter = &time
		}
	}
	if notBefore != nil && notAfter != nil && !notBefore.Before(*notAfter) {
		http.Error(resp, "invalid order in time constraints", http.StatusBadRequest)
		return
	}

	// allocate the new order and populate it
	order := account.NewOrder()
	account.mux.Lock()
	defer account.mux.Unlock()
	order.Status = AcmeStatusPending
	order.RequestNotBefore = payload.NotBefore
	order.RequestNotAfter = payload.NotAfter
	order.ExpiryTime = time.Now().Add(OrderTimeWindow)
	for _, ident := range payload.Identifier {
		order.Authorizations = append(order.Authorizations, AcmeAuthorization{
			Identifier:    ident.Value,
			Status:        AcmeStatusPending,
			Token:         rand.Text(),
			ChallengeType: "http-01",
		})
	}

	// return the created order
	sendOrderResource(http.StatusCreated, order, url, resp)
}
func handleAccount(state *AcmeState, url *url.URL, req *http.Request, resp http.ResponseWriter) {
	// resolve the account and payload and validate them
	rawPayload, account := processPostAsGet(state, url, req, resp)
	if rawPayload == nil {
		return
	}
	if len(rawPayload) != 0 {
		http.Error(resp, "malformed request payload", http.StatusBadRequest)
		return
	}
	account.mux.Lock()
	defer account.mux.Unlock()

	// return the found account
	sendAccountResource(http.StatusOK, account, url, resp)
}
func handleOrders(state *AcmeState, url *url.URL, req *http.Request, resp http.ResponseWriter) {
	// resolve the account and payload and validate them
	rawPayload, account := processPostAsGet(state, url, req, resp)
	if rawPayload == nil {
		return
	}
	if len(rawPayload) != 0 {
		http.Error(resp, "malformed request payload", http.StatusBadRequest)
		return
	}
	account.mux.Lock()
	defer account.mux.Unlock()

	// construct the list of orders
	orders := []string{}
	for id := range account.Orders {
		orders = append(orders, makeFullURL(url, fmt.Sprintf("/order/%v", id)))
	}

	// return the requested list of orders
	respondWithJson(http.StatusOK, resp, map[string]any{
		"orders": orders,
	})
}
func handleOrder(state *AcmeState, url *url.URL, req *http.Request, resp http.ResponseWriter) {
	// lookup the order id
	var orderIdentifier string
	if index := strings.Index(url.Path, "/order/"); index == -1 {
		http.Error(resp, "malformed order identifier", http.StatusNotFound)
		return
	} else {
		orderIdentifier = url.Path[index+7:]
	}

	// resolve the account and payload and validate them
	rawPayload, account := processPostAsGet(state, url, req, resp)
	if rawPayload == nil {
		return
	}
	if len(rawPayload) != 0 {
		http.Error(resp, "malformed request payload", http.StatusBadRequest)
		return
	}

	// lookup the order
	order := account.LookupOrderById(orderIdentifier)
	if order == nil {
		http.Error(resp, "unknown order identifier", http.StatusNotFound)
		return
	}

	// return the found order
	account.mux.Lock()
	defer account.mux.Unlock()
	order.UpdateOrder()
	sendOrderResource(http.StatusOK, order, url, resp)
}
func handleAuth(state *AcmeState, url *url.URL, req *http.Request, resp http.ResponseWriter) {
	// lookup the order id and auth index
	var orderIdentifier string
	var idIndex int
	if indexId := strings.Index(url.Path, "/auth/"); indexId == -1 {
		http.Error(resp, "malformed authorization identifier", http.StatusNotFound)
		return
	} else if indexIndex := strings.Index(url.Path[indexId+6:], "/"); indexIndex == -1 {
		http.Error(resp, "malformed authorization identifier", http.StatusNotFound)
		return
	} else {
		indexIndex += indexId + 6
		orderIdentifier = url.Path[indexId+6 : indexIndex]
		var err error
		if idIndex, err = strconv.Atoi(url.Path[indexIndex+1:]); err != nil {
			http.Error(resp, "malformed authorization identifier", http.StatusNotFound)
			return
		}
	}

	// resolve the account and payload and validate them
	rawPayload, account := processPostAsGet(state, url, req, resp)
	if rawPayload == nil {
		return
	}
	if len(rawPayload) != 0 {
		http.Error(resp, "malformed request payload", http.StatusBadRequest)
		return
	}

	// lookup the order
	order := account.LookupOrderById(orderIdentifier)
	if order == nil {
		http.Error(resp, "unknown order identifier", http.StatusNotFound)
		return
	}
	account.mux.Lock()
	defer account.mux.Unlock()
	order.UpdateOrder()

	// lookup the authentication index
	if idIndex >= len(order.Authorizations) {
		http.Error(resp, "unknown authorization identifier", http.StatusNotFound)
		return
	}
	auth := &order.Authorizations[idIndex]

	// return the found authorization
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
	// lookup the order id and auth index
	var orderIdentifier string
	var idIndex int
	if indexId := strings.Index(url.Path, "/challenge/"); indexId == -1 {
		http.Error(resp, "malformed challenge identifier", http.StatusNotFound)
		return
	} else if indexIndex := strings.Index(url.Path[indexId+11:], "/"); indexIndex == -1 {
		http.Error(resp, "malformed challenge identifier", http.StatusNotFound)
		return
	} else {
		indexIndex += indexId + 11
		orderIdentifier = url.Path[indexId+11 : indexIndex]
		var err error
		if idIndex, err = strconv.Atoi(url.Path[indexIndex+1:]); err != nil {
			http.Error(resp, "malformed challenge identifier", http.StatusNotFound)
			return
		}
	}

	// resolve the account and payload and validate them
	rawPayload, account := processPostAsGet(state, url, req, resp)
	if rawPayload == nil {
		return
	}
	if !bytes.Equal(rawPayload, []byte("{}")) {
		http.Error(resp, "malformed request payload", http.StatusBadRequest)
		return
	}

	// lookup the order
	order := account.LookupOrderById(orderIdentifier)
	if order == nil {
		http.Error(resp, "unknown order identifier", http.StatusNotFound)
		return
	}
	account.mux.Lock()
	defer account.mux.Unlock()
	order.UpdateOrder()

	// lookup the authentication index
	if idIndex >= len(order.Authorizations) {
		http.Error(resp, "unknown authorization identifier", http.StatusNotFound)
		return
	}
	auth := &order.Authorizations[idIndex]

	// check if the status should be toggled to 'ready'
	if auth.Status == AcmeStatusPending {
		// TODO: implement actual challenge validation/verification
		auth.Status = AcmeStatusValid
		auth.Validated = time.Now().Format(time.RFC3339Nano)
	}

	// return the challenge
	respondWithJson(http.StatusOK, resp, map[string]any{
		"type":      auth.ChallengeType,
		"url":       makeFullURL(url, fmt.Sprintf("/challenge/%v/%v", orderIdentifier, idIndex)),
		"status":    string(auth.Status),
		"token":     auth.Token,
		"validated": auth.Validated,
	})
}
func handleFinalize(state *AcmeState, url *url.URL, req *http.Request, resp http.ResponseWriter) {
	// lookup the order id
	var orderIdentifier string
	if index := strings.Index(url.Path, "/finalize/"); index == -1 {
		http.Error(resp, "malformed finalize identifier", http.StatusNotFound)
		return
	} else {
		orderIdentifier = url.Path[index+10:]
	}

	// resolve the account
	rawPayload, account := processPostAsGet(state, url, req, resp)
	if rawPayload == nil {
		return
	}

	// lookup the order
	order := account.LookupOrderById(orderIdentifier)
	if order == nil {
		http.Error(resp, "unknown order identifier", http.StatusNotFound)
		return
	}

	// return the found order
	account.mux.Lock()
	defer account.mux.Unlock()
	order.UpdateOrder()

	// validate the state
	if order.Status != AcmeStatusReady {
		sendOrderResource(http.StatusOK, order, url, resp)
		return
	}

	// TODO: validate final CSR in payload and provide the certificate
	http.Error(resp, "not yet implemented", http.StatusInternalServerError)
}
