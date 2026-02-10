package main

import "log"

func main() {
	srv, err := NewServer()
	if err != nil {
		log.Fatal(err)
	}
	log.Fatal(srv.Run(":8080"))
}
