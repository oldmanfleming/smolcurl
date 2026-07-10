package main

import (
	"log"
	"os"
)

func main() {
	url := os.Args[1:2][0]
	resp, err := send("GET", url)
	if err != nil {
		log.Fatalf("could not send for url: %v %v", url, err)
	}
	log.Printf("response: %v", resp)
}
