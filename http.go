package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
)

func send(rawURL string) (string, error) {
	if rawURL == "" {
		return "", errors.New("empty url")
	}

	url, err := parseURL(rawURL)
	if err != nil {
		return "", fmt.Errorf("parsing url: %w", err)
	}

	log.Printf("parsed scheme: %v, hostname: %v, port:%v, path: %v", url.scheme, url.host, url.port, url.path)

	conn, err := dial(url.host, url.port)
	if err != nil {
		return "", fmt.Errorf("dialing connection: %w", err)
	}
	defer conn.Close()

	log.Printf("opened connection: %+v", conn)

	return "", nil
}

// Meaty parts:
// - Request.write() seems to do a lot of the http specific writing to the writer
// - persistConn seems to be the wrapper around the tcp connection
// - Transport.getConn() opens the persistConn and sets up TLS

// client.go
//
//	Client.do(Request)
//	Client.send(Request)
//	send(Request, RoundTripper) -- RoundTripper = Transport
//
// roundtrip.go
//
//	RoundTripper.RoundTrip(Request)
//
// transport.go
//
//	Transport.roundTrip(Request)
//	  Transport.getConn(transportRequest, connectMethod) persistConn
//		transport maintains a queue and getConn queues a request for a connection
//		and then waits to receive the resulting persistent connection
//		Transport.dialConn()
//			Transport.dial("tcp", address string)
//				Transport.Dial() -- Where is this defined?
//
// dialer.go
//
//	Dialer.Dial() -> Dialer.DialContext()
//		sysDialer.dialParallel()
//			sysDialer.dialSerial
//				sysDialer.dialSingle
//
// tcpsock_posix.go
//
//	sysDialer.dialTCP -> sysDialer.doDialTCP -> sysDialer.doDialTCPProto
func temp() {
	http.Get("https://example.com")
}
