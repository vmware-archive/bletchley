// Package bletchly is a simple, high-level library for asymmetric encryption and decryption.
package bletchley

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
)

// EncryptedMessage is an encrypted (but not authenticated) representation of a plaintext message.
// The consumer of this package should not need to understand or manipulate the fields except for serialization.
// Decryption requires possession of the private key.
type EncryptedMessage struct {
	Ciphertext   []byte
	EncryptedKey []byte
}

// Encrypt encrypts a given plaintext using the provided public key.
// The encryption process uses random data. Therefore, this function is not deterministic.
func Encrypt(publicKey *rsa.PublicKey, plaintext []byte) (EncryptedMessage, error) {
	if publicKey == nil {
		return EncryptedMessage{}, errors.New("public key must not be nil")
	}

	aesKey, err := generateSymmetricKey()
	if err != nil {
		return EncryptedMessage{}, err
	}

	ciphertext, err := symmetricEncrypt(aesKey, plaintext)
	if err != nil {
		return EncryptedMessage{}, err
	}

	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, aesKey, nil)
	if err != nil {
		return EncryptedMessage{}, err
	}

	return EncryptedMessage{
		Ciphertext:   ciphertext,
		EncryptedKey: encryptedKey,
	}, nil
}

// Decrypt decrypts a given EncryptedMessage using the provided private key.
// If the provided key is invalid then Decrypt will return an empty slice and an error.
// Decrypt does not validate the authenticity of the encrypted message.
func Decrypt(privateKey *rsa.PrivateKey, msg EncryptedMessage) ([]byte, error) {
	if privateKey == nil {
		return []byte{}, errors.New("private key must not be nil")
	}

	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, msg.EncryptedKey, nil)
	if err != nil {
		return []byte{}, err
	}

	return symmetricDecrypt(aesKey, msg.Ciphertext)
}
