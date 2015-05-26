// Package bletchly is a simple, high-level library for asymmetric encryption and decryption.
package bletchley

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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

// Decrypt decrypts a given EncryptedMessage using the provided private key.
// If the provided key is invalid then Decrypt will return an empty slice and an error.
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
