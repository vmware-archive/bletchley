package bletchley_test

import (
	"crypto/rand"
	"crypto/rsa"

	"github.com/pivotal-cf-experimental/bletchley"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var cipher bletchley.Cipher

var _ = Describe("Generating asymmetric key pairs", func() {
	It("should return a 4096 bit key pair", func() {
		private, public, err := cipher.Generate()
		Expect(err).NotTo(HaveOccurred())

		Expect(public).To(Equal(private.Public()))
		Expect(public.N.BitLen()).To(Equal(4096))
	})
})

var _ = Describe("Serialization of asymmetric keys", func() {
	var privateKey *rsa.PrivateKey

	BeforeEach(func() {
		nbits := 256
		var err error
		privateKey, err = rsa.GenerateKey(rand.Reader, nbits)
		Expect(err).To(BeNil())
	})

	Describe("private keys", func() {
		It("should serialize and deserialize losslessly", func() {
			pemBytes := cipher.PrivateKeyToPEM(privateKey)

			Expect(cipher.PEMToPrivateKey(pemBytes)).To(Equal(privateKey))
		})
	})

	Describe("public keys", func() {
		It("should serialize and deserialize losslessly", func() {
			publicKey := privateKey.Public().(*rsa.PublicKey)

			pemBytes, err := cipher.PublicKeyToPEM(publicKey)
			Expect(err).NotTo(HaveOccurred())

			Expect(cipher.PEMToPublicKey(pemBytes)).To(Equal(publicKey))
		})
	})
})
