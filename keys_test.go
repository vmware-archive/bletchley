package bletchley_test

import (
	"crypto/rand"
	"crypto/rsa"

	"github.com/pivotal-cf-experimental/bletchley"

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

var _ = Describe("Generating keys", func() {
	It("should not error", func() {
		private, public, err := bletchley.Generate()

		Expect(private).ToNot(BeNil())
		Expect(public).ToNot(BeNil())
		Expect(err).To(BeNil())

	})

	It("should return a public key that is derived from the private key", func() {
		private, public, _ := bletchley.Generate()
		publicKey := private.Public().(*rsa.PublicKey)
		Expect(publicKey).To(Equal(public))
	})

	It("should return a public key that has the correct length", func() {
		_, public, _ := bletchley.Generate()
		Expect(public.N.BitLen()).To(Equal(4096))
	})
})
