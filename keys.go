package bletchley

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

const (
	PEMHeaderPrivateKey = "RSA PRIVATE KEY"
	PEMHeaderPublicKey  = "PUBLIC KEY"
)

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

// PublicKeyFromPEM loads an RSA public key from raw bytes found in a .pem file.
func PublicKeyFromPEM(rawBytes []byte) (*rsa.PublicKey, error) {
	keyBytes, err := loadAndValidatePEM(rawBytes, PEMHeaderPublicKey)
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

// PrivateKeyFromPEM loads an RSA private key from raw bytes found in a .pem or .key file.
func PrivateKeyFromPEM(rawBytes []byte) (*rsa.PrivateKey, error) {
	keyBytes, err := loadAndValidatePEM(rawBytes, PEMHeaderPrivateKey)
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

	return encodePEM(keyBytes, PEMHeaderPrivateKey)
}

// PublicKeyToPEM serializes an RSA Public key into PEM format.
func PublicKeyToPEM(publicKey *rsa.PublicKey) ([]byte, error) {
	keyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return []byte{}, err
	}

	return encodePEM(keyBytes, PEMHeaderPublicKey), nil
}

// Generate creates a 2048-bit RSA key pair.
func Generate() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	keySize := 2048
	private, err := rsa.GenerateKey(randomReader, keySize)
	if err != nil {
		return nil, nil, err
	}
	public := private.Public().(*rsa.PublicKey)
	return private, public, nil
}
