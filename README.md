#Bletchley
[![Build Status](https://api.travis-ci.org/pivotal-cf-experimental/bletchley.png?branch=master)](http://travis-ci.org/pivotal-cf-experimental/bletchley)
[![GoDoc](https://godoc.org/github.com/pivotal-cf-experimental/bletchley?status.svg)](https://godoc.org/github.com/pivotal-cf-experimental/bletchley)

Bletchley is a simple, high-level Go library and command-line tool for asymmetric encryption and decryption.

It implements a basic [hybrid cryptosystem](http://en.wikipedia.org/wiki/Hybrid_cryptosystem) by
[wrapping functionality](http://en.wikipedia.org/wiki/Facade_pattern) in the Go standard library.


Design goals:
- Easy to use
- Idiot-proof
- Use standard, open formats

Design non-goals:
- **Authentication**
- Performance
- Flexibility
- Determinism


## Example usage of command line tool
##### Install the command-line binary
```bash
go get -u github.com/pivotal-cf-experimental/bletchley/bletchley
```

##### Generate a keypair and save it to disk
```bash
bletchley -o generate -public public_key.pem -private private_key.pem
```

##### Encrypt some data using the public key
```bash
echo "this is a secret message" | bletchley -o encrypt -public public_key.pem > encrypted.json
```

##### Decrypt data using the private key
```bash
cat encrypted.json | bletchley -o decrypt -private private_key.pem
```


## Example usage of library
Look at the [CLI tool](https://github.com/pivotal-cf-experimental/bletchley/blob/master/bletchley/main.go) for a full working example.  Look at the [Godoc](https://godoc.org/github.com/pivotal-cf-experimental/bletchley) for a complete reference.

##### Generate a keypair and save it to disk
```go
privateKey, publicKey, err := bletchley.Generate()

privateKeyPEM := bletchley.PrivateKeyToPEM(privateKey)
err := ioutil.WriteFile("private_key.pem", privateKeyPEM, os.FileMode(0600))

publicKeyPEM, err := bletchley.PublicKeyToPEM(publicKey)
err = ioutil.WriteFile("public_key.pem", publicKeyPEM, os.FileMode(0644))
```

##### Load keys from disk
```go
privateKeyPEM, err := ioutil.ReadFile("private_key.pem")
privateKey, err := bletchley.PEMToPrivateKey(privateKeyPEM)

publicKeyPEM, err := ioutil.ReadFile("public_key.pem")
publicKey, err := bletchley.PEMToPublicKey(publicKeyPEM)
```

##### Encrypt some data using the public key
```go
plaintextBytes := []byte("this is a secret message")
encryptedMessage, err := bletchley.Encrypt(publicKey, plaintextBytes)
encryptedBytes, err := json.Marshal(encryptedMessage)
err = ioutil.WriteFile("encrypted.json", encryptedBytes, os.FileMode(0644))
```

##### Decrypt data using the private key
```go
encryptedBytes, err := ioutil.ReadFile("encrypted.json")
var encryptedMessage bletchley.EncryptedMessage
err = json.Unmarshal(encryptedBytes, &encryptedMessage)
plaintextBytes, err := bletchley.Decrypt(privateKey, encrypted)
```

## Frequently asked questions

#### Why no authentication?
Bletchley **does not authenticate messages**.  You must rely on an external mechanism to prevent or detect tampering of encrypted messages.
Authentication would require the sender to have a secret, either an asymmetric private key
for a [digital signature](http://en.wikipedia.org/wiki/Digital_Signature_Algorithm)
or a symmetric secret for [message authentication](http://en.wikipedia.org/wiki/Message_authentication_code).
That is out of scope for this project.


#### Why is the GCM nonce hardcoded to zeros?
Looking at the code in [`symmetric.go`](https://github.com/pivotal-cf-experimental/bletchley/blob/master/symmetric.go)
you'll see we're using zero bytes for the "nonce" in the symmetric encryption step.  This is justified for two reasons:

1. We use each symmetric key for exactly one message.  Each key is created from a
[cryptographically strong pseudo-random generator](https://godoc.org/crypto/rand#pkg-variables),
used once, asymmetrically encrypted, and never re-used.
See Section 8.2.1 of [NIST Special Publication 800-38D](http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf) for details on nonce requirements when the key is one-time-use.  See also [this discussion of AEAD nonces](https://www.imperialviolet.org/2015/05/16/aeads.html), which covers the zero nonce case.

2. We make no authentication assurances (see above), but nonce uniqueness is only required for the authentication guarantees of GCM,
 not for the secrecy guarantees.  This is detailed in Appendix A of the same
[NIST document](http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf).

#### Why use symmetric ciphers internally?
The math of asymmetric cryptography requires that the message not be longer than the public key.
Therefore, we implement a [hybrid cryptosystem](http://en.wikipedia.org/wiki/Hybrid_cryptosystem) where arbitrary-length plaintext is
first symmetrically encrypted using a strong random key, and that key is then asymmetrically encrypted.  This is the standard approach to solving the message length issue.

#### Why use RSA and not Elliptic Curve Cryptography?
The Go standard library implements RSA, and [ECDSA](https://golang.org/pkg/crypto/ecdsa/), but not [ECIES](http://en.wikipedia.org/wiki/Integrated_Encryption_Scheme).
While there appears to be at least one partial implementation of ECIES in Go, we're reluctant to depend on anything outside the standard library.
