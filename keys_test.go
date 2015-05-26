package bletchley_test

import (
	"crypto/rand"
	"crypto/rsa"

	"github.com/rosenhouse/bletchley"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Serialization and deserialization of asymmetric keys", func() {
	It("preserves data through serialization and deserialization", func() {
		nbits := 256
		privateKey, err := rsa.GenerateKey(rand.Reader, nbits)
		Expect(err).To(BeNil())

		pemBytes := bletchley.PrivateKeyToPEM(privateKey)

		unmarshalled, err := bletchley.PrivateKeyFromPEM(pemBytes)
		Expect(err).To(BeNil())

		Expect(unmarshalled).To(Equal(privateKey))

		reserialized := bletchley.PrivateKeyToPEM(unmarshalled)

		Expect(reserialized).To(Equal(pemBytes))

		Expect(unmarshalled.Public()).To(Equal(privateKey.Public()))
	})

	It("preserves data through serialization and deserialization", func() {
		nbits := 256
		privateKey, err := rsa.GenerateKey(rand.Reader, nbits)
		Expect(err).To(BeNil())

		publicKey := privateKey.Public().(*rsa.PublicKey)

		pemBytes, err := bletchley.PublicKeyToPEM(publicKey)
		Expect(err).NotTo(HaveOccurred())

		unmarshalled, err := bletchley.PublicKeyFromPEM(pemBytes)
		Expect(err).NotTo(HaveOccurred())

		Expect(unmarshalled).To(Equal(publicKey))

		reserialized, err := bletchley.PublicKeyToPEM(unmarshalled)
		Expect(err).NotTo(HaveOccurred())

		Expect(reserialized).To(Equal(pemBytes))
	})
})
