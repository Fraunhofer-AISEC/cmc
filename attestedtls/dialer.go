package attestedtls

import (
	"crypto/tls"
	"errors"
	log "github.com/sirupsen/logrus"
)

// Wraps tls.Dial
// Additionally performs remote attestation
// before returning the established connection.
func Dial(network, addr string, config *tls.Config) (*tls.Conn, error) {
	//use mTLS if client provides its own certificate
	mTLS := (config.Certificates != nil)

	// Create TLS connection
	conn, err := tls.Dial(network, addr, config)
	if err != nil {
		log.Error(err)
		return nil, errors.New("[Dialer] TLS establishment failed")
	}

	// Perform remote attestation
	// include components of tls.Conn to link both protocols: use peer (server) cert
	// FUTURE: check if certificate can be obtained differently
	err = verify(conn, conn.ConnectionState().PeerCertificates[0].Raw[:])
	if err != nil {
		log.Error(err)
		return nil, errors.New("[Dialer] Failed to verify Listener")
	}

	if mTLS {
		log.Info("[Dialer] Performing mTLS: verifying dialer...")
		// attest itself: include own certificate in AR
		// Future: check if certificate can be obtained differently
		err = attest(conn, config.Certificates[0].Certificate[0])
		if err != nil {
			log.Error(err)
			return nil, errors.New("[Dialer] remote verification of dialer failed")
		}
	} else {
		log.Info("[Dialer] No mTLS performed")
	}

	// finished
	log.Info("[Listener] Client-side aTLS connection complete")
	return conn, nil
}
