package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type URL struct {
	scheme string
	host   string
	port   int
	path   string
}

func parseURL(rawURL string) (URL, error) {
	var (
		scheme, host, path string
		port               int
	)

	scheme, rest, err := parseValidScheme(rawURL)
	if err != nil {
		return URL{}, fmt.Errorf("parsing scheme: %w", err)
	}

	if !strings.HasPrefix(rest, "//") {
		return URL{}, errors.New("invalid url format")
	}
	rest = rest[2:]

	var hostport string
	if i := strings.LastIndex(rest, "/"); i == 0 {
		return URL{}, errors.New("empty host")
	} else if i > 0 {
		hostport = rest[:i]
		path = rest[i+1:]
	} else {
		hostport = rest
		path = ""
	}

	host, port, err = parseHostPort(scheme, hostport)
	if err != nil {
		return URL{}, fmt.Errorf("bad host/port format: %w", err)
	}

	return URL{
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
