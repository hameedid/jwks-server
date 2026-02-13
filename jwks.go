package main

import (
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"time"
)

type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type JWKS struct {
	Keys []JWK `json:"keys"`
}

func b64urlBigInt(n *big.Int) string {
	return base64.RawURLEncoding.EncodeToString(n.Bytes())
}

func b64urlInt(e int) string {
	b := big.NewInt(int64(e)).Bytes()
	return base64.RawURLEncoding.EncodeToString(b)
}

func publicJWKFromKeypair(kp KeyPair) JWK {
	pub := kp.Private.PublicKey
	return JWK{
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		Kid: kp.KID,
		N:   b64urlBigInt(pub.N),
		E:   b64urlInt(pub.E),
	}
}

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	now := time.Now()
	keys := []JWK{}

	if !s.KS.Active.IsExpired(now) {
		keys = append(keys, publicJWKFromKeypair(s.KS.Active))
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(JWKS{Keys: keys})
}
