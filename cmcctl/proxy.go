package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	atls "github.com/Fraunhofer-AISEC/cmc/attestedtls"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	pub "github.com/Fraunhofer-AISEC/cmc/publish"
)

type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

var hopByHopHeaders = []string{
	"Proxy-Connection",
	"Keep-Alive",
	"TE",
	"Transfer-Encoding",
	"Upgrade",
	"Connection",
}

// This function forwards all data between conn1 and conn2 until either both connections are at EOF
// or the context ctx is cancelled.
func proxyRawConnections(ctx context.Context, conn1, conn2 net.Conn) {
	localCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var ctxCancelled atomic.Bool

	go func() {
		<-localCtx.Done()
		ctxCancelled.Store(true)
		deadline := time.Now().Add(time.Millisecond)
		// We set really small read deadlines to get the reading goroutines to wake up
		conn1.SetReadDeadline(deadline)
		conn2.SetReadDeadline(deadline)
	}()

	var wg sync.WaitGroup
	forward := func(from, to net.Conn) {
		defer wg.Done()
		_, err := io.Copy(to, from)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) && ctxCancelled.Load() {
				// This error is due to the context being canceled, ignore
			} else {
				log.Debugf("Error forwarding data from %s to %s: %v", from.RemoteAddr(), to.RemoteAddr(), err)
			}
		}
		// To comply with the spec, the connection must be closed once one connection is closed.
		cancel()
	}

	wg.Add(2)
	go forward(conn1, conn2)
	go forward(conn2, conn1)
	wg.Wait()
}

func proxyHttpRequest(proxyTransport *http.Transport, c *config, w http.ResponseWriter, req *http.Request) {
	log.Debug("Using standard HTTP proxy mode")

	via := req.Header.Get("Via")
	// Check the Via header to verify that we are not in a routing loop (RFC 9110, sec. 7.6.3)
	if via != "" {
		for hop := range strings.SplitSeq(via, ",") {
			if strings.Contains(hop, c.Addr) {
				http.Error(w, "Proxy loop detected", http.StatusLoopDetected)
				log.Debug("Proxy loop detected")
				return
			}
		}
		via = via + ", "
	}

	newReq := req.Clone(req.Context())

	// Add ourselves to the Via header (RFC 9110, sec 7.6.3)
	newReq.Header.Set("Via", fmt.Sprintf("%s%d.%d %s", via, req.ProtoMajor, req.ProtoMinor, c.Addr))

	// Remove connection and known hop-by-hop headers from the request (RFC 9110, sec 7.6.1)
	var filteredHeaders []string
	filteredHeaders = append(filteredHeaders, hopByHopHeaders...)
	connection := req.Header.Get("Connection")
	for field := range strings.SplitSeq(connection, ",") {
		filteredHeaders = append(filteredHeaders, strings.TrimSpace(field))
	}
	for _, header := range hopByHopHeaders {
		newReq.Header.Del(header)
	}

	// Note: We are explicitly not using http.Client.Do here as that would handle cookies, redirects, etc.
	// which we want to forward to the client.
	resp, err := proxyTransport.RoundTrip(newReq)
	if err != nil {
		log.Debugf("Failed to forward http request to %s: %s", req.URL, err)
		http.Error(w, fmt.Sprintf("Failed to proxy request: %s", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		log.Debugf("Error forwarding to the client: %v", err)
	}
}

func proxyTunnel(dial dialFunc, c *config, w http.ResponseWriter, req *http.Request) {
	log.Debug("Using HTTP CONNECT tunneling")

	h, ok := w.(http.Hijacker)
	if !ok {
		log.Warn("The underlying HTTP implementation does not support connection hijacking")
		http.Error(w, "HTTP CONNECT tunneling is not supported by this proxy", http.StatusNotImplemented)
		return
	}

	// The connect proxy scheme only supports parsing host and port (required, since no protocol is allowed).
	// We should also reject URLs here that contains anything else, but let's let that slide in the name of compatibility.
	if req.URL.Port() == "" {
		http.Error(w, "No port provided", http.StatusBadRequest)
		return
	}
	toServer, err := dial(req.Context(), "tcp", req.URL.Host)
	if err != nil {
		log.Debugf("Failed to dial remote server %s: %s", req.URL.Host, err)
		// TODO: Depending on the error, this is also a bad request (e.g. if the remote address rejects)
		http.Error(w, fmt.Sprintf("Failed to dial remote server: %s", err), http.StatusInternalServerError)
		return
	}
	defer toServer.Close()

	// TODO: It might also be interesting to forward some attestation related information to the caller via X-* headers.
	w.WriteHeader(http.StatusOK)

	toClient, buffered, err := h.Hijack()
	if err != nil {
		log.Debugf("Error hijacking HTTP connection: %v", err)
		return
	}
	defer toClient.Close()

	// The error can be ignored since we peek the exact length of the buffer
	buf, _ := buffered.Reader.Peek(buffered.Reader.Buffered())

	// The HTTP server may have already received some client data.
	n, err := toServer.Write(buf)
	if n != len(buf) {
		err = fmt.Errorf("could not write all available data to the destination")
	}
	if err != nil {
		log.Debugf("Error forwarding buffered data to server: %v", err)
		return
	}

	// TODO(http2): Respect connection multiplexing instead of hijacking
	proxyRawConnections(req.Context(), toClient, toServer)
}

// The forward proxy acts as a general purpose HTTP proxy over an attested TLS tunnel.
// It supports the HTTP CONNECT method to forward arbitrary TCP-based protocols over the TLS tunnel.
//
// The HTTP proxy implementation follows RFC 9110, section 7.6.
// The semantics of the HTTP CONNECT method are defined in RFC 9110, section 9.3.6.
// Note that the HTTP CONNECT proxy currently breaks HTTP2 connections.
func forwardProxy(c *config) error {
	var tlsConf *tls.Config

	// Add trusted server root CAs
	trustedRootCas := x509.NewCertPool()
	for _, ca := range c.identityCas {
		trustedRootCas.AddCert(ca)
	}

	if c.Mtls {
		// Load own certificate
		var cert tls.Certificate
		cert, err := atls.GetCert(
			atls.WithCmcAddr(c.CmcAddr),
			atls.WithCmcApi(c.Api),
			atls.WithApiSerializer(c.apiSerializer),
			atls.WithLibApiCmcConfig(&c.Config))
		if err != nil {
			return fmt.Errorf("failed to get TLS Certificate: %w", err)
		}
		// Create TLS config with root CA and own certificate
		tlsConf = &tls.Config{
			Certificates: []tls.Certificate{cert},
			RootCAs:      trustedRootCas,
		}
	} else {
		// Create TLS config with root CA only
		tlsConf = &tls.Config{
			RootCAs:       trustedRootCas,
			Renegotiation: tls.RenegotiateNever,
		}
	}

	internal.PrintTlsConfig(tlsConf, c.identityCas)

	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		log.Debugf("Dialing TLS address: %v", addr)

		conn, err := atls.Dial("tcp", addr, tlsConf,
			atls.WithCmcAddr(c.CmcAddr),
			atls.WithCmcPolicies(c.policies),
			atls.WithCmcApi(c.Api),
			atls.WithApiSerializer(c.apiSerializer),
			atls.WithMtls(c.Mtls),
			atls.WithAttest(c.attest),
			atls.WithResultCb(func(result *ar.AttestationResult) {
				// Publish the attestation result asynchronously if publishing address was specified and
				// and attestation was performed
				if c.attest == atls.Attest_Mutual || c.attest == atls.Attest_Server {
					wg := new(sync.WaitGroup)
					wg.Add(1)
					defer wg.Wait()
					go pub.PublishResultAsync(c.Publish, c.publishToken, c.ResultFile, result, wg)
				}
			}),
			atls.WithLibApiCmcConfig(&c.Config))
		if err != nil {
			return nil, fmt.Errorf("failed to dial server: %w", err)
		}

		return conn, err
	}

	// We always want to dial over a TLS connection for both http and https proxy requests
	proxyTransport := &http.Transport{
		DialContext:    dial,
		DialTLSContext: dial,
	}

	proxyHandler := func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodConnect {
			proxyTunnel(dial, c, w, req)
		} else {
			proxyHttpRequest(proxyTransport, c, w, req)
		}
	}

	log.Infof("Starting HTTP proxy on %s", c.Addr)

	return http.ListenAndServe(c.Addr, http.HandlerFunc(proxyHandler))
}
