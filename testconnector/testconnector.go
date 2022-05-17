package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"io/ioutil"
	"net"

	log "github.com/sirupsen/logrus"

	// local modules
	atls "github.com/Fraunhofer-AISEC/cmc/attestedtls"
)

func main() {
	var cert tls.Certificate
	var err error
	var config *tls.Config

	rootCACertFile := flag.String("rootcacertfile", "ca.pem", "TLS Certificate of CA / Entity that is RoT of the connector's TLS certificate")
	connectoraddress := flag.String("connector", "0.0.0.0:443", "ip:port on which to listen")
	flag.Parse()

	log.SetLevel(log.TraceLevel)

	// get root CA cert
	rootCA, err := ioutil.ReadFile(*rootCACertFile)
	if err != nil {
		log.Error("[Testclient] Could find root CA cert file.")
		return
	}

	// Add root CA
	roots := x509.NewCertPool()
	success := roots.AppendCertsFromPEM(rootCA)
	if !success {
		log.Error("[Testclient] Could not add cert to root CAs.")
		return
	}

	// Load certificate
	cert, err = atls.GetCert()
	if err != nil {
		log.Error("[Testconnector] failed to get TLS Certificate. ", err)
		return
	}

	// Create TLS config
	config = &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.VerifyClientCertIfGiven, // make mTLS an option
		ClientCAs:    roots,
	}

	// Listen: TLS connection
	ln, err := atls.Listen("tcp", *connectoraddress, config)
	if err != nil {
		log.Error(err)
		log.Error("[Testconnector] Failed to listen for connections")
		return
	}
	defer ln.Close()

	for {
		log.Info("[Testconnector] serving under " + *connectoraddress)
		// Finish TLS connection establishment with Remote Attestation
		conn, err := ln.Accept()
		if err != nil {
			log.Error(err)
			log.Error("[Testconnector] Failed to establish connection")
			continue
		}
		// Handle established connections
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	r := bufio.NewReader(conn)

	// read
	msg, err := r.ReadString('\n')
	if err != nil {
		log.Error(err)
		log.Error("[Testconnector] Failed to read")
		return
	}
	println(msg)

	// write
	_, err = conn.Write([]byte("answer to : " + msg + "\n"))
	if err != nil {
		log.Error(err)
		log.Error("[Testconnector] Failed to write")
		return
	}
}
