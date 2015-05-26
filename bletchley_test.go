package bletchley_test

import (
	"crypto/rand"
	"crypto/rsa"

	"github.com/rosenhouse/bletchley"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Encrypt / decrypt cycle", func() {
	It("preserves data through encryption and decryption", func() {
		message := []byte("this is a secret message")

		nbits := 1024
		privateKey, err := rsa.GenerateKey(rand.Reader, nbits)
		Expect(err).To(BeNil())

		publicKey := privateKey.Public().(*rsa.PublicKey)

		encrypted, err := bletchley.Encrypt(publicKey, message)
		Expect(err).To(BeNil())

		decrypted, err := bletchley.Decrypt(privateKey, encrypted)
		Expect(err).To(BeNil())

		Expect(decrypted).To(Equal(message))
	})
})
