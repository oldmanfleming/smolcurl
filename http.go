package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
)

type url struct {
	scheme string
	host   string
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

	log.Printf("parsed scheme: %v, host: %v, path: %v", url.scheme, url.host, url.path)

	log.Printf("resolving address of host: %v", url.host)
	address, err := resolve(url.host, TypeA)
	if err != nil {
		return "", fmt.Errorf("resolving address: %w", err)
	}

	log.Printf("resolved address: %v", address)

	return address, nil
}

func parseURL(rawURL string) (url, error) {
	var scheme, host, path string
	scheme, rest, err := parseScheme(rawURL)
	if err != nil {
		return url{}, fmt.Errorf("parsing scheme: %w", err)
	}
	scheme = strings.ToLower(scheme)

	if !strings.HasPrefix(rest, "//") {
		return url{}, errors.New("invalid url format")
	}
	rest = rest[2:]

	if i := strings.LastIndex(rest, "/"); i == 0 {
		return url{}, errors.New("empty host")
	} else if i > 0 {
		host = rest[:i]
		path = rest[i+1:]
	} else {
		host = rest
		path = ""
	}

	return url{
		scheme,
		host,
		path,
	}, nil
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

func temp() {
	http.Get("https://example.com")
}
