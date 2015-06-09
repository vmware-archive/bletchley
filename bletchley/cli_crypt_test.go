package main_test

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("encrypting and decrypting", func() {
	Context("when the keys are correctly generated", func() {
		It("should decrypt to the same plaintext that was encrypted", func() {
			run("-o", "generate", "-private", privateKeyPath, "-public", publicKeyPath)

			plaintext := "this is a secret"

			stdoutEncrypted, stderr, err := runWithStdin(plaintext, "-o", "encrypt", "-public", publicKeyPath)

			Expect(err).NotTo(HaveOccurred())
			Expect(stderr).To(BeEmpty())
			Expect(stdoutEncrypted).NotTo(BeEmpty())

			stdoutDecrypted, stderr, err := runWithStdin(stdoutEncrypted, "-o", "decrypt", "-private", privateKeyPath)

			Expect(err).NotTo(HaveOccurred())
			Expect(stderr).To(BeEmpty())
			Expect(stdoutDecrypted).To(Equal(plaintext))
		})
	})

	Context("when trying to decrypt with an incorrect private key", func() {
		It("should error and exit non-zero", func() {
			run("-o", "generate", "-private", privateKeyPath, "-public", publicKeyPath)

			wrongPrivateKeyPath := newTempFilename("wrong-private-key")
			wrongPublicKeyPath := newTempFilename("wrong-public-key")

			run("-o", "generate", "-private", wrongPrivateKeyPath, "-public", wrongPublicKeyPath)

			plaintext := "this is a secret"

			stdoutEncrypted, stderr, err := runWithStdin(plaintext, "-o", "encrypt", "-public", publicKeyPath)

			Expect(err).NotTo(HaveOccurred())
			Expect(stderr).To(BeEmpty())
			Expect(stdoutEncrypted).NotTo(BeEmpty())

			stdoutDecrypted, stderr, err := runWithStdin(stdoutEncrypted, "-o", "decrypt", "-private", wrongPrivateKeyPath)

			Expect(err).To(HaveOccurred())
			Expect(stderr).To(Equal("crypto/rsa: decryption error\n"))
			Expect(stdoutDecrypted).To(BeEmpty())
		})
	})
})
