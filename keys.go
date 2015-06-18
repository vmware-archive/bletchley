package bletchley

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

const (
	pemHeaderPrivateKey = "RSA PRIVATE KEY"
	pemHeaderPublicKey  = "PUBLIC KEY"
	keySize             = 4096
)

// Generate creates a 4096-bit RSA key pair.
func Generate() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	private, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, nil, err
	}
	public := private.Public().(*rsa.PublicKey)
	return private, public, nil
}

func loadAndValidatePEM(rawBytes []byte, expectedType string) ([]byte, error) {
	pemBlock, _ := pem.Decode(rawBytes)
	if pemBlock == nil {
		return nil, fmt.Errorf("No PEM data found.")
	}

	if pemBlock.Type != expectedType {
		return nil, fmt.Errorf("Expected PEM data of type %q but instead found %q", expectedType, pemBlock.Type)
	}

	return pemBlock.Bytes, nil
}

// PEMToPublicKey converts raw bytes found in a .pem file into an RSA public key
func PEMToPublicKey(rawBytes []byte) (*rsa.PublicKey, error) {
	keyBytes, err := loadAndValidatePEM(rawBytes, pemHeaderPublicKey)
	if err != nil {
		return nil, err
	}

	pub, err := x509.ParsePKIXPublicKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse public key: %s", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("Public key must be an RSA public key")
	}
	return rsaPub, nil
}

// PEMToPrivateKey converts raw bytes found in a .pem or .key file into an RSA private key
func PEMToPrivateKey(rawBytes []byte) (*rsa.PrivateKey, error) {
	keyBytes, err := loadAndValidatePEM(rawBytes, pemHeaderPrivateKey)
	if err != nil {
		return nil, err
	}

	priv, err := x509.ParsePKCS1PrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse private key: %s", err)
	}

	return priv, nil
}

func encodePEM(keyBytes []byte, keyType string) []byte {
	block := &pem.Block{
		Type:  keyType,
		Bytes: keyBytes,
	}

	return pem.EncodeToMemory(block)
}

// PrivateKeyToPEM serializes an RSA Private key into PEM format.
func PrivateKeyToPEM(privateKey *rsa.PrivateKey) []byte {
	keyBytes := x509.MarshalPKCS1PrivateKey(privateKey)

	return encodePEM(keyBytes, pemHeaderPrivateKey)
}

// PublicKeyToPEM serializes an RSA Public key into PEM format.
func PublicKeyToPEM(publicKey *rsa.PublicKey) ([]byte, error) {
	keyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return []byte{}, err
	}

	return encodePEM(keyBytes, pemHeaderPublicKey), nil
}
