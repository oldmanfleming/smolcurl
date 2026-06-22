package main

import (
	"log"
	"os"
)

func main() {
	name := os.Args[1:2][0]
	ip, err := resolve(name, TypeA)
	if err != nil {
		log.Fatalf("failed to execute query: %v", err)
	}
	log.Printf("resolved: %v", ip)
}
