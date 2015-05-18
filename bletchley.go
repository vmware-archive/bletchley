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

type Cipher struct {
	hash   hash.Hash
	random io.Reader
}

func (c *Cipher) randomBytes(n int) ([]byte, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return []byte{}, err
	}
	return bytes, nil
}

func New() *Cipher {
	return &Cipher{
		hash:   sha256.New(),
		random: rand.Reader,
	}
}

type EncryptedMessage struct {
	Nonce        []byte `json:"nonce"`
	Ciphertext   []byte `json:"ciphertext"`
	EncryptedKey []byte `json:"encrypted_key"`
}

func PublicKeyFromPEM(keyBytes []byte) (*rsa.PublicKey, error) {
	pemBlock, _ := pem.Decode(keyBytes)
	if pemBlock == nil {
		return nil, fmt.Errorf("No PEM data found.")
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
	return rsaPub, nil
}

func PrivateKeyFromPEM(keyBytes []byte) (*rsa.PrivateKey, error) {
	pemBlock, _ := pem.Decode(keyBytes)
	if pemBlock == nil {
		return nil, fmt.Errorf("No PEM data found.")
	}

	const expectedType = "RSA PRIVATE KEY"
	if pemBlock.Type != expectedType {
		return nil, fmt.Errorf("Expected PEM data type of %q but found %q", expectedType, pemBlock.Type)
	}

	priv, err := x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("Failed to parse private key: %s", err)
	}

	return priv, nil
}

func (c *Cipher) Encrypt(publicKey *rsa.PublicKey, plaintext []byte) (EncryptedMessage, error) {
	aesKey, err := c.randomBytes(symmetricKeyLength)
	if err != nil {
		return EncryptedMessage{}, err
	}

	nonce, err := c.randomBytes(symmetricNonceLength)
	if err != nil {
		return EncryptedMessage{}, err
	}

	symPayload, err := symmetricEncrypt(aesKey, nonce, plaintext)
	if err != nil {
		return EncryptedMessage{}, err
	}

	encryptedKey, err := rsa.EncryptOAEP(c.hash, c.random, publicKey, aesKey, nil)
	if err != nil {
		return EncryptedMessage{}, err
	}

	return EncryptedMessage{
		Nonce:        symPayload.Nonce,
		Ciphertext:   symPayload.Ciphertext,
		EncryptedKey: encryptedKey,
	}, nil
}

func (c *Cipher) Decrypt(privateKey *rsa.PrivateKey, msg EncryptedMessage) ([]byte, error) {
	aesKey, err := rsa.DecryptOAEP(c.hash, c.random, privateKey, msg.EncryptedKey, nil)
	if err != nil {
		return []byte{}, fmt.Errorf("RSA decryption: " + err.Error())
	}

	plaintext, err := symmetricDecrypt(aesKey, gcmPayload{msg.Nonce, msg.Ciphertext})
	if err != nil {
		return []byte{}, fmt.Errorf("GCM AES decryption: " + err.Error())
	}

	return plaintext, nil
}
