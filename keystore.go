package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"time"
)

type KeyPair struct {
	KID       string
	ExpiresAt time.Time
	Private   *rsa.PrivateKey
}

type KeyStore struct {
	Active  KeyPair
	Expired KeyPair
}

// random KID (good enough for this assignment)
func newKID() (string, error) {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func generateRSAKey() (*rsa.PrivateKey, error) {
	// 2048-bit RSA key
	return rsa.GenerateKey(rand.Reader, 2048)
}

func NewKeyStore() (*KeyStore, error) {
	now := time.Now()

	activePriv, err := generateRSAKey()
	if err != nil {
		return nil, err
	}
	activeKID, err := newKID()
	if err != nil {
		return nil, err
	}

	expiredPriv, err := generateRSAKey()
	if err != nil {
		return nil, err
	}
	expiredKID, err := newKID()
	if err != nil {
		return nil, err
	}

	return &KeyStore{
		Active: KeyPair{
			KID:       activeKID,
			ExpiresAt: now.Add(1 * time.Hour),
			Private:   activePriv,
		},
		Expired: KeyPair{
			KID:       expiredKID,
			ExpiresAt: now.Add(-1 * time.Hour),
			Private:   expiredPriv,
		},
	}, nil
}

func (kp KeyPair) IsExpired(at time.Time) bool {
	// expired if at >= ExpiresAt
	return !at.Before(kp.ExpiresAt)
}
