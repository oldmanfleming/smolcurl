package main

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
)

const HTTP_VERSION = "HTTP/1.1"

func send(method string, url string) (string, error) {
	if url == "" {
		return "", errors.New("empty url")
	}

	u, err := parseURL(url)
	if err != nil {
		return "", fmt.Errorf("parsing url: %w", err)
	}

	log.Printf("parsed scheme: %v, hostname: %v, port:%v, path: %v", u.scheme, u.host, u.port, u.path)

	conn, err := dial(u.host, u.port)
	if err != nil {
		return "", fmt.Errorf("dialing connection: %w", err)
	}
	defer conn.Close()
	log.Printf("opened connectio: %v - %v", conn.LocalAddr().String(), conn.RemoteAddr().String())

	resp, err := exec(conn, method, u.path, u.host, u.port)
	if err != nil {
		return "", fmt.Errorf("executing request: %w", err)
	}
	log.Printf("got response: %v", resp)

	return "", nil
}

func exec(conn net.Conn, method string, path string, host string, port int) (string, error) {
	reqLine := fmt.Sprintf("%v %v %v \r\n", method, path, HTTP_VERSION)
	headerLine := fmt.Sprintf("host: %v:%v \r\n", host, port)
	req := fmt.Sprintf("%v%v\r\n", reqLine, headerLine)

	log.Printf("constructed req: \n%v", req)

	n, err := fmt.Fprint(conn, req)

	if err != nil {
		return "", fmt.Errorf("writing req: %v", err)
	}

	log.Printf("wrote bytes: %v", n)

	reader := bufio.NewReader(conn)
	resp, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("reading resp: %v", err)
	}
	log.Printf("read resp with len %v: %s", n, resp)
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
