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
	"sync"
	"sync/atomic"
	"time"

	ar "github.com/Fraunhofer-AISEC/cmc/attestationreport"
	atls "github.com/Fraunhofer-AISEC/cmc/attestedtls"
	"github.com/Fraunhofer-AISEC/cmc/internal"
	pub "github.com/Fraunhofer-AISEC/cmc/publish"
)

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

// The forward proxy uses the HTTP CONNECT method to forward arbitrary TCP connections over an
// attested TLS connection.
// The semantics of the HTTP CONNECT method are defined in RFC 9110, section 9.3.6.
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

	proxyHandler := func(w http.ResponseWriter, req *http.Request) {
		log := log.WithField("client", req.RemoteAddr)

		if req.Method != http.MethodConnect {
			http.Error(w, "Only HTTP CONNECT requests are supported", http.StatusMethodNotAllowed)
			return
		}

		// The connect proxy scheme only supports parsing host and port (required, since no protocol is allowed).
		// We should also reject URLs here that contains anything else, but let's let that slide in the name of compatibility.
		if req.URL.Port() == "" {
			http.Error(w, "No port provided", http.StatusBadRequest)
			return
		}
		toServer, err := atls.Dial("tcp", req.URL.Host, tlsConf,
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
			log.Debugf("Failed to dial remote server %s: %s", req.URL.Host, err)
			// TODO: Depending on the error, this is also a bad request (e.g. if the remote address rejects)
			http.Error(w, fmt.Sprintf("Failed to dial remote server: %s", err), http.StatusInternalServerError)
			return
		}
		defer toServer.Close()

		// TODO: It might also be interesting to forward some attestation related information to the caller via X-* headers.
		w.WriteHeader(http.StatusNoContent)

		h, ok := w.(http.Hijacker)
		if !ok {
			// This is an OK panic I think since this feature is supported by the go default server.
			panic("The HTTP server implementation does not support connection hijacking")
		}

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

		proxyRawConnections(req.Context(), toClient, toServer)

		log.Debug("Connection closed")
	}

	log.Infof("Starting HTTP CONNECT proxy on %s", c.Addr)
	return http.ListenAndServe(c.Addr, http.HandlerFunc(proxyHandler))
}
