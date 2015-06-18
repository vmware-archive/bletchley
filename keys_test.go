package bletchley_test

import (
	"crypto/rand"
	"crypto/rsa"

	"github.com/pivotal-cf-experimental/bletchley"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Generating asymmetric key pairs", func() {
	It("should return a 4096 bit key pair", func() {
		private, public, err := bletchley.Generate()
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
			pemBytes := bletchley.PrivateKeyToPEM(privateKey)

			Expect(bletchley.PEMToPrivateKey(pemBytes)).To(Equal(privateKey))
		})
	})

	Describe("public keys", func() {
		It("should serialize and deserialize losslessly", func() {
			publicKey := privateKey.Public().(*rsa.PublicKey)

			pemBytes, err := bletchley.PublicKeyToPEM(publicKey)
			Expect(err).NotTo(HaveOccurred())

			Expect(bletchley.PEMToPublicKey(pemBytes)).To(Equal(publicKey))
		})
	})
})
