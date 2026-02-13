package main

import (
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func (s *Server) handleAuth(w http.ResponseWriter, r *http.Request) {
	
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	now := time.Now()

	
	useExpired := r.URL.Query().Has("expired")

	var kp KeyPair
	var exp time.Time

	if useExpired {
		kp = s.KS.Expired
		exp = now.Add(-1 * time.Minute) 
	} else {
		kp = s.KS.Active
		exp = now.Add(5 * time.Minute) 
	}

	claims := jwt.MapClaims{
		"sub": "fake-user",
		"iss": "jwks-server",
		"iat": now.Unix(),
		"exp": exp.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	token.Header["kid"] = kp.KID

	signed, err := token.SignedString(kp.Private)
	if err != nil {
		http.Error(w, "failed to sign token", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"token":"` + signed + `"}`))
}
