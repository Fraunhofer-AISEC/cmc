package main

import (
	"bufio"
	"crypto/tls"
	log "github.com/sirupsen/logrus"
	"net"
	// local modules
	atls "github.com/Fraunhofer-AISEC/cmc/attestedtls"
)

var (
	serveraddress = "localhost"
	serverport    = "4443"
)

func main() {
	var cert tls.Certificate
	var err error
	var config *tls.Config

	log.SetLevel(log.TraceLevel)

	// Load certificate
	cert, err = atls.GetCert()
	if err != nil {
		log.Error("[Testserver] failed to get TLS Certificate. \n", err)
		return
	}
	config = &tls.Config{
		Certificates: []tls.Certificate{cert},
		// ClientAuth:   tls.RequireAndVerifyClientCert, // FUTURE: enforce mTLS
	}

	// Listen: Tls connection
	ln, err := atls.Listen("tcp", serveraddress+":"+serverport, config)
	if err != nil {
		log.Error("[Testserver] Failed to listen for connections. \n", err)
		return
	}
	defer ln.Close()

	for {
		log.Info("[Testserver] serving under " + serveraddress + ":" + serverport)
		// Finish TLS connection establishment with Remote Attestation
		conn, err := ln.Accept()
		if err != nil {
			log.Error("[Testserver] Failed to establish connection. \n", err)
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
		log.Error("[Testserver] Failed to read. \n", err)
		return
	}
	println(msg)

	// write
	_, err = conn.Write([]byte("answer to : " + msg + "\n"))
	if err != nil {
		log.Error("[Testserver] Failed to write. \n", err)
		return
	}
}
