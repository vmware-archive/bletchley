package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

type symmetric struct {
	streamCipher cipher.AEAD
	aesKey       []byte
	gcmNonce     []byte
}

func cryptoRandomBytes(n int) ([]byte, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return []byte{}, err
	}
	return bytes, nil
}

func generateSymmetric() (*symmetric, error) {
	aesKey, err := cryptoRandomBytes(32)
	if err != nil {
		return nil, err
	}

	gcmNonce, err := cryptoRandomBytes(12)
	if err != nil {
		return nil, err
	}

	return loadSymmetric(aesKey, gcmNonce)
}

func loadSymmetric(aesKey, gcmNonce []byte) (*symmetric, error) {
	blockCipher, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	streamCipher, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}

	return &symmetric{
		aesKey:       aesKey,
		gcmNonce:     gcmNonce,
		streamCipher: streamCipher,
	}, nil
}

func (s *symmetric) encrypt(plaintext []byte) []byte {
	return s.streamCipher.Seal(nil, s.gcmNonce, plaintext, nil)
}

func (s *symmetric) decrypt(ciphertext []byte) ([]byte, error) {
	return s.streamCipher.Open(nil, s.gcmNonce, ciphertext, nil)
}
