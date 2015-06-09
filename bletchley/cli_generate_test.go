package main_test

import (
	"io/ioutil"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("generating keys with the CLI tool", func() {
	Context("when a private key path is not specified", func() {
		It("should print a private key to stdout", func() {
			stdout, stderr, err := run("-o", "generate")

			Expect(err).NotTo(HaveOccurred())
			Expect(stderr).To(BeEmpty())
			Expect(stdout).To(HavePrefix("-----BEGIN RSA PRIVATE KEY-----"))
			Expect(stdout).To(HaveSuffix("-----END RSA PRIVATE KEY-----\n"))
		})
	})

	Context("when an invalid private key path is given", func() {
		It("should print an error and exit non-zero", func() {
			stdout, stderr, err := run("-o", "generate", "-private", "/$@!~/NOT/A/PATH")

			Expect(err).To(HaveOccurred())
			Expect(stdout).To(BeEmpty())
			Expect(stderr).To(ContainSubstring("Error writing private key file"))
			Expect(stderr).To(ContainSubstring("/$@!~/NOT/A/PATH: no such file or directory"))
		})
	})

	Context("when a valid private key path is given", func() {
		It("should save the private key to the file path and not print it to stdout", func() {
			stdout, stderr, err := run("-o", "generate", "-private", privateKeyPath)

			Expect(err).NotTo(HaveOccurred())
			Expect(stdout).To(BeEmpty())
			Expect(stderr).To(BeEmpty())

			privKey, _ := ioutil.ReadFile(privateKeyPath)
			Expect(privKey).To(HavePrefix("-----BEGIN RSA PRIVATE KEY-----"))
			Expect(privKey).To(HaveSuffix("-----END RSA PRIVATE KEY-----\n"))
		})
	})

	Context("when valid private and public key paths are given", func() {
		It("should save both keys and not print to stdout", func() {
			stdout, stderr, err := run("-o", "generate", "-private", privateKeyPath, "-public", publicKeyPath)

			Expect(err).NotTo(HaveOccurred())
			Expect(stdout).To(BeEmpty())
			Expect(stderr).To(BeEmpty())

			privKey, _ := ioutil.ReadFile(privateKeyPath)
			pubKey, _ := ioutil.ReadFile(publicKeyPath)

			Expect(privKey).To(HavePrefix("-----BEGIN RSA PRIVATE KEY-----"))
			Expect(privKey).To(HaveSuffix("-----END RSA PRIVATE KEY-----\n"))

			Expect(pubKey).To(HavePrefix("-----BEGIN PUBLIC KEY-----"))
			Expect(pubKey).To(HaveSuffix("-----END PUBLIC KEY-----\n"))
		})
	})
})
