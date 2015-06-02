#Bletchley
[![Build Status](https://api.travis-ci.org/pivotal-cf-experimental/bletchley.png?branch=master)](http://travis-ci.org/pivotal-cf-experimental/bletchley)
[![GoDoc](https://godoc.org/github.com/pivotal-cf-experimental/bletchley?status.svg)](https://godoc.org/github.com/pivotal-cf-experimental/bletchley)

Bletchley is a simple, high-level Go library and command-line tool for asymmetric encryption and decryption.

It implements a basic [hybrid cryptosystem](http://en.wikipedia.org/wiki/Hybrid_cryptosystem) using the Go standard library.

Design goals:
- Easy to use
- Idiot-proof
- Use standard, open formats

Design non-goals:
- Authentication of plaintexts
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
privateKey, err := bletchley.PrivateKeyFromPEM(privateKeyPEM)

publicKeyPEM, err := ioutil.ReadFile("public_key.pem")
publicKey, err := bletchley.PublicKeyFromPEM(publicKeyPEM)
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


