package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
)

type url struct {
	scheme string
	host   string
	port   int
	path   string
}

func get(rawURL string) (string, error) {
	if rawURL == "" {
		return "", errors.New("empty url")
	}

	url, err := parseURL(rawURL)
	if err != nil {
		return "", fmt.Errorf("parsing url: %w", err)
	}

	log.Printf("parsed scheme: %v, host: %v, port:%v, path: %v", url.scheme, url.host, url.port, url.path)

	addr, err := resolveAddress(url.host)
	if err != nil {
		return "", fmt.Errorf("resolving address: %w", err)
	}

	// conn, err := dial(addr, url.port)
	// if err != nil {
	// 	return "", fmt.Errorf("dialing connection: %w", err)
	// }

	return addr, nil
}

func parseURL(rawURL string) (url, error) {
	var (
		scheme, host, path string
		port               int
	)

	scheme, rest, err := parseValidScheme(rawURL)
	if err != nil {
		return url{}, fmt.Errorf("parsing scheme: %w", err)
	}

	if !strings.HasPrefix(rest, "//") {
		return url{}, errors.New("invalid url format")
	}
	rest = rest[2:]

	var hostport string
	if i := strings.LastIndex(rest, "/"); i == 0 {
		return url{}, errors.New("empty host")
	} else if i > 0 {
		hostport = rest[:i]
		path = rest[i+1:]
	} else {
		hostport = rest
		path = ""
	}

	host, port, err = parseHostPort(scheme, hostport)
	if err != nil {
		return url{}, fmt.Errorf("bad host/port format: %w", err)
	}

	return url{
		scheme,
		host,
		port,
		path,
	}, nil
}

func parseValidScheme(url string) (string, string, error) {
	scheme, rest, err := parseScheme(url)
	if err != nil {
		return "", "", fmt.Errorf("parsing scheme: %w", err)
	}
	scheme = strings.ToLower(scheme)
	switch scheme {
	case "http", "https":
		return scheme, rest, nil
	default:
		return "", "", fmt.Errorf("Unsupported scheme: %v", scheme)
	}
}

func parseScheme(url string) (string, string, error) {
	for i, c := range url {
		if 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' {
			continue
		} else if '0' <= c && c <= '9' || c == '+' || c == '-' || c == '.' {
			if i == 0 {
				return "", "", errors.New("scheme must start with a letter")
			}
			continue
		} else if c == ':' {
			if i == 0 {
				return "", "", errors.New("scheme must not be empty")
			}
			return url[:i], url[i+1:], nil
		} else {
			return "", "", errors.New("invalid character in scheme")
		}
	}
	return "", "", errors.New("empty url")
}

func parseHostPort(scheme string, hostport string) (string, int, error) {
	if hostport == "" {
		return "", -1, errors.New("empty hostport")
	}
	// port is specified after the last colon of the full hostport combo
	i := strings.LastIndexByte(hostport, ':')
	// if no port is specified, we resolve it using the scheme
	if i < 0 {
		port, err := resolvePort(scheme)
		if err != nil {
			return "", -1, fmt.Errorf("resolving port: %w", err)
		}
		return hostport, port, nil
	}
	// we expect at least one port character if the colon was specified
	if i == len(hostport)-1 {
		return "", -1, errors.New("no port after colon")
	}
	port, err := strconv.Atoi(hostport[i+1:])
	if err != nil {
		return "", -1, errors.New("port must be an interger")
	}
	if port < 0 || port > 65535 {
		return "", -1, errors.New("invalid port number")
	}
	return hostport[:i], port, nil
}

func resolvePort(scheme string) (int, error) {
	switch scheme {
	case "http":
		return 80, nil
	case "https":
		return 553, nil
	default:
		return -1, errors.New("unknown port for specified scheme")
	}
}

// TODO: try to parse as IP address, otherwise resolve
func resolveAddress(host string) (string, error) {
	log.Printf("resolving address of host: %v", host)
	addr, err := resolve(host, TypeA)
	if err != nil {
		return "", fmt.Errorf("resolving address: %w", err)
	}
	log.Printf("resolved address: %v", addr)
	return addr, nil
}

func dial(addr string, port int) (net.Conn, error) {
	ip := net.ParseIP(addr)
	conn, err := net.DialTCP("tcp", nil, &net.TCPAddr{
		IP:   ip,
		Port: port,
	})
	if err != nil {
		return nil, fmt.Errorf("could not dial address: %w", err)
	}
	return conn, nil
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
