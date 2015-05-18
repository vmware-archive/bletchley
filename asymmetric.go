package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
)

func readPublicKey(keyPath string) (*rsa.PublicKey, error) {
	return nil, errors.New("foo")
}

func readPrivateKey(keyPath string) (*rsa.PrivateKey, error) {
	return nil, errors.New("bar")
}

type asymmetric struct {
	hash   hash.Hash
	random io.Reader
}

type asymmetricEncrypter struct {
	asymmetric
	publicKey *rsa.PublicKey
}

type asymmetricDecrypter struct {
	asymmetric
	privateKey *rsa.PrivateKey
}

func loadAsymmetricEncrypter(keyPath string) (*asymmetricEncrypter, error) {
	keyBytes, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	pemBlock, _ := pem.Decode(keyBytes)
	if pemBlock == nil {
		return nil, fmt.Errorf("No PEM data found in %q", keyPath)
	}
	const expectedType = "PUBLIC KEY"
	if pemBlock.Type != expectedType {
		return nil, fmt.Errorf("Expected PEM data type of %q but found %q", expectedType, pemBlock.Type)
	}

	pub, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse public key: %s", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("Public key must be an RSA public key")
	}
	return &asymmetricEncrypter{
		asymmetric: asymmetric{
			hash:   sha256.New(),
			random: rand.Reader,
		},
		publicKey: rsaPub,
	}, nil
}

func loadAsymmetricDecrypter(keyPath string) (*asymmetricDecrypter, error) {
	keyBytes, err := ioutil.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	pemBlock, _ := pem.Decode(keyBytes)
	if pemBlock == nil {
		return nil, fmt.Errorf("No PEM data found in %q", keyPath)
	}

	const expectedType = "RSA PRIVATE KEY"
	if pemBlock.Type != expectedType {
		return nil, fmt.Errorf("Expected PEM data type of %q but found %q", expectedType, pemBlock.Type)
	}

	priv, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse private key: %s", err)
	}

	return &asymmetricDecrypter{
		asymmetric: asymmetric{
			hash:   sha256.New(),
			random: rand.Reader,
		},
		privateKey: priv,
	}, nil
}

func (a *asymmetricEncrypter) encrypt(plaintext []byte) ([]byte, error) {
	return rsa.EncryptOAEP(a.hash, a.random, a.publicKey, plaintext, nil)
}

func (a *asymmetricDecrypter) decrypt(ciphertext []byte) ([]byte, error) {
	return rsa.DecryptOAEP(a.hash, a.random, a.privateKey, ciphertext, nil)
}
