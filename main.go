package main

import (
	"log"
	"os"
)

func main() {
	url := os.Args[1:2][0]
	resp, err := get(url)
	if err != nil {
		log.Fatalf("could not get from url: %v %v", url, err)
	}
	log.Printf("response: %v", resp)
}
