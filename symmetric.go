package bletchley

import (
	"crypto/aes"
	"crypto/cipher"
)

const (
	symmetricNonceLength = 12
	symmetricKeyLength   = 32
)

// We are allowed to use an empty nonce because we never re-use keys
// see Section 8.2.1 of NIST Special Publication 800-38D
// http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf
var zeroNonce []byte = make([]byte, symmetricNonceLength)

func symmetricDecrypt(aesKey, ciphertext []byte) ([]byte, error) {
	blockCipher, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	streamCipher, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}

	return streamCipher.Open(nil, zeroNonce, ciphertext, nil)
}

func symmetricEncrypt(aesKey, plaintext []byte) ([]byte, error) {
	blockCipher, err := aes.NewCipher(aesKey)
	if err != nil {
		return []byte{}, err
	}

	streamCipher, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return []byte{}, err
	}

	ciphertext := streamCipher.Seal(nil, zeroNonce, plaintext, nil)
	return ciphertext, nil
}
