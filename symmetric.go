package bletchley

import (
	"crypto/aes"
	"crypto/cipher"
)

type gcmPayload struct {
	Nonce      []byte
	Ciphertext []byte
}

func symmetricDecrypt(aesKey []byte, msg gcmPayload) ([]byte, error) {
	blockCipher, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	streamCipher, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}

	return streamCipher.Open(nil, msg.Nonce, msg.Ciphertext, nil)
}

func symmetricEncrypt(aesKey []byte, nonce []byte, plaintext []byte) (gcmPayload, error) {
	blockCipher, err := aes.NewCipher(aesKey)
	if err != nil {
		return gcmPayload{}, err
	}

	streamCipher, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return gcmPayload{}, err
	}

	ciphertext := streamCipher.Seal(nil, nonce, plaintext, nil)
	return gcmPayload{nonce, ciphertext}, nil
}

const (
	symmetricNonceLength = 12
	symmetricKeyLength   = 32
)
