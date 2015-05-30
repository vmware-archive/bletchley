package bletchley

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

const (
	symmetricNonceLength = 12
	symmetricKeyLength   = 32
)

// We are allowed to use an empty nonce because we never re-use keys
// see Section 8.2.1 of NIST Special Publication 800-38D
// http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf
var zeroNonce []byte = make([]byte, symmetricNonceLength)

func generateSymmetricKey() ([]byte, error) {
	bytes := make([]byte, symmetricKeyLength)
	if _, err := rand.Read(bytes); err != nil {
		return []byte{}, err
	}
	return bytes, nil
}

func makeAESGCM(aesKey []byte) (cipher.AEAD, error) {
	blockCipher, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(blockCipher)
}

func symmetricDecrypt(aesKey, ciphertext []byte) ([]byte, error) {
	gcm, err := makeAESGCM(aesKey)
	if err != nil {
		return nil, err
	}

	return gcm.Open(nil, zeroNonce, ciphertext, nil)
}

func symmetricEncrypt(aesKey, plaintext []byte) ([]byte, error) {
	gcm, err := makeAESGCM(aesKey)
	if err != nil {
		return nil, err
	}

	return gcm.Seal(nil, zeroNonce, plaintext, nil), nil
}
