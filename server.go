package main

import (
	"log"
	"net/http"
)

type Server struct {
	KS *KeyStore
}

func NewServer() (*Server, error) {
	ks, err := NewKeyStore()
	if err != nil {
		return nil, err
	}
	return &Server{KS: ks}, nil
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", s.handleJWKS)

	mux.HandleFunc("/auth", s.handleAuth)

	return mux
}

func (s *Server) Run(addr string) error {
	log.Printf("Listening on %s", addr)
	return http.ListenAndServe(addr, s.routes())
}
