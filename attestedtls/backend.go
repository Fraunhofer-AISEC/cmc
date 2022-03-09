package attestedtls

import (
	"context"
	"net"
	"encoding/binary"
	"errors"
	"google.golang.org/grpc"
	"time"
	log "github.com/sirupsen/logrus"
	// local modules
	ci "github.com/Fraunhofer-AISEC/cmc/cmcinterface"
)

var cmcaddr = "localhost"
var cmcport = "9955"

/***********************************************************
* Backend to CMC
*/

func getCMCServiceConn() (ci.CMCServiceClient, *grpc.ClientConn, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), 5* time.Second)
	conn, err := grpc.DialContext(ctx, cmcaddr + ":" + cmcport, grpc.WithInsecure(), grpc.WithBlock())
	if err != nil {
		log.Error("[Backend] ERROR: did not connect:", err)
		cancel()
		return nil, nil, nil
	}

	log.Trace("[Backend] Creating new service client")
	return ci.NewCMCServiceClient(conn), conn, cancel
}


/***********************************************************
* Backend between two connectors / client and connector
*/

func Write(msg []byte, c net.Conn) error {

	lenbuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenbuf, uint32(len(msg)))

	buf := append(lenbuf, msg...)

	_, err := c.Write(buf)

	return err
}

func Read(c net.Conn) ([]byte, error) {

	lenbuf := make([]byte, 4)
	n, err := c.Read(lenbuf)

	if err != nil {
		log.Error(err)
		return nil, errors.New("[Backend] Failed to receive message: no length.")
	}

	len := binary.BigEndian.Uint32(lenbuf) // Max size of 4GB
	log.Trace("TCP Message Length: ", len)

	if len == 0 {
		return nil, errors.New("[Backend] Message length is zero")
	}

	// Receive data in chunks of 1024 bytes as the Read function receives a maxium of 65536 bytes
	// and the buffer must be longer, then append it to the final buffer
	tmpbuf := make([]byte, 1024)
	buf := make([]byte, 0)
	rcvlen := uint32(0)

	for {
		n, err = c.Read(tmpbuf)
		rcvlen += uint32(n)
		if err != nil {
			log.Error(err)
			return nil, errors.New("[Backend] Failed to receive message")
		}
		buf = append(buf, tmpbuf[:n]...)

		// Abort as soon as we have read the expected data as signaled in the first 4 bytes
		// of the message
		if rcvlen == len {
			log.Trace("[Backend] Received message")
			break
		}
	}
	return buf, nil
}
