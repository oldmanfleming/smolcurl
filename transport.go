package main

import (
	"fmt"
	"log"
	"net"
)

func dial(host string, port int) (net.Conn, error) {
	ip, err := resolveIP(host)
	if err != nil {
		return nil, fmt.Errorf("thing: %w", err)
	}

	conn, err := net.DialTCP("tcp", nil, &net.TCPAddr{
		IP:   ip,
		Port: port,
	})
	if err != nil {
		return nil, fmt.Errorf("could not dial address: %w", err)
	}

	return conn, nil
}

func resolveIP(host string) (net.IP, error) {
	ip := net.ParseIP(host)
	if ip != nil {
		return ip, nil
	}

	addr, err := resolve(host, TypeA)
	if err != nil {
		return net.IP{}, fmt.Errorf("resolving address: %w", err)
	}

	log.Printf("resolved address: %v", addr)

	ip = net.ParseIP(addr)
	if ip == nil {
		return nil, fmt.Errorf("resolved invalid ip: %+v", ip)
	}

	return ip, nil
}
