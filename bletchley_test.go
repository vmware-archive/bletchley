package bletchley_test

import (
	"crypto/rand"
	"crypto/rsa"

	"github.com/pivotal-cf-experimental/bletchley"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Encrypt / decrypt cycle", func() {
	var (
		privateKey *rsa.PrivateKey
		publicKey  *rsa.PublicKey
	)

	BeforeEach(func() {
		nbits := 1024
		var err error
		privateKey, err = rsa.GenerateKey(rand.Reader, nbits)
		Expect(err).NotTo(HaveOccurred())

		publicKey = privateKey.Public().(*rsa.PublicKey)
	})

	It("should encrypt and decrypt without data loss", func() {
		message := []byte("this is a secret message")

		encrypted, err := bletchley.Encrypt(publicKey, message)
		Expect(err).NotTo(HaveOccurred())

		decrypted, err := bletchley.Decrypt(privateKey, encrypted)
		Expect(err).NotTo(HaveOccurred())

		Expect(decrypted).To(Equal(message))
	})

	It("should handle plaintext messages longer than the asymmetric key", func() {
		longMessage := make([]byte, 1024*1024)
		Expect(rand.Read(longMessage)).To(Equal(len(longMessage)))

		encrypted, err := bletchley.Encrypt(publicKey, longMessage)
		Expect(err).NotTo(HaveOccurred())

		decrypted, err := bletchley.Decrypt(privateKey, encrypted)
		Expect(err).NotTo(HaveOccurred())

		Expect(decrypted).To(Equal(longMessage))
	})

	Context("when the public key is too short", func() {
		It("should return an error", func() {
			var err error
			privateKey, err = rsa.GenerateKey(rand.Reader, 512)
			Expect(err).NotTo(HaveOccurred())
			publicKey = privateKey.Public().(*rsa.PublicKey)

			_, err = bletchley.Encrypt(publicKey, []byte("foo"))
			Expect(err).To(MatchError(rsa.ErrMessageTooLong))
		})

	})
})
