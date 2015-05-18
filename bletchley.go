// Package bletchley provides high-level functionality for asymmetric encryption and decryption.
package bletchley

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"hash"
	"io"
)

var (
	_hash hash.Hash = sha256.New()

	randomReader io.Reader = rand.Reader
)

func randomBytes(n int) ([]byte, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return []byte{}, err
	}
	return bytes, nil
}

// EncryptedMessage is the encrypted and authenticated representation of a plaintext message.
// The consumer of this package should not need to understand or manipulate the fields except for serialization.
// Decryption requires possession of the private key.
type EncryptedMessage struct {
	Nonce        []byte `json:"nonce"`
	Ciphertext   []byte `json:"ciphertext"`
	EncryptedKey []byte `json:"encrypted_key"`
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

// PublicKeyFromPEM loads an RSA public key from raw bytes found in a .pem file
func PublicKeyFromPEM(rawBytes []byte) (*rsa.PublicKey, error) {
	keyBytes, err := loadAndValidatePEM(rawBytes, "PUBLIC KEY")
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

// PrivateKeyFromPEM loads an RSA private key from raw bytes found in a .pem or .key file
func PrivateKeyFromPEM(rawBytes []byte) (*rsa.PrivateKey, error) {
	keyBytes, err := loadAndValidatePEM(rawBytes, "RSA PRIVATE KEY")
	if err != nil {
		return nil, err
	}

	priv, err := x509.ParsePKCS1PrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse private key: %s", err)
	}

	return priv, nil
}

// Encrypt encrypts a given plaintext using the provided public key.
func Encrypt(publicKey *rsa.PublicKey, plaintext []byte) (EncryptedMessage, error) {
	aesKey, err := randomBytes(symmetricKeyLength)
	if err != nil {
		return EncryptedMessage{}, err
	}

	nonce, err := randomBytes(symmetricNonceLength)
	if err != nil {
		return EncryptedMessage{}, err
	}

	symPayload, err := symmetricEncrypt(aesKey, nonce, plaintext)
	if err != nil {
		return EncryptedMessage{}, err
	}

	encryptedKey, err := rsa.EncryptOAEP(_hash, randomReader, publicKey, aesKey, nil)
	if err != nil {
		return EncryptedMessage{}, err
	}

	return EncryptedMessage{
		Nonce:        symPayload.Nonce,
		Ciphertext:   symPayload.Ciphertext,
		EncryptedKey: encryptedKey,
	}, nil
}

// Decrypt decrypts a given EncryptedMessage using the provided private key
// If the provided key is invalid or the message has been tampered with, Decrypt will return an empty slice and an error.
func Decrypt(privateKey *rsa.PrivateKey, msg EncryptedMessage) ([]byte, error) {
	aesKey, err := rsa.DecryptOAEP(_hash, randomReader, privateKey, msg.EncryptedKey, nil)
	if err != nil {
		return []byte{}, fmt.Errorf("RSA decryption: " + err.Error())
	}

	plaintext, err := symmetricDecrypt(aesKey, gcmPayload{msg.Nonce, msg.Ciphertext})
	if err != nil {
		return []byte{}, fmt.Errorf("GCM AES decryption: " + err.Error())
	}

	return plaintext, nil
}
