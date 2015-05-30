#Bletchley
[![Build Status](https://api.travis-ci.org/pivotal-cf-experimental/bletchley.png?branch=master)](http://travis-ci.org/pivotal-cf-experimental/bletchley)
[![GoDoc](https://godoc.org/github.com/pivotal-cf-experimental/bletchley?status.svg)](https://godoc.org/github.com/pivotal-cf-experimental/bletchley)

Bletchley is a high-level Go library and command-line tool for asymmetric encryption and decryption.

It implements a [hybrid cryptosystem](http://en.wikipedia.org/wiki/Hybrid_cryptosystem) using primitives from the Go standard library.

Design goals:
- Easy to use
- Idiot-proof
- Use standard, open formats

Design non-goals:
- Authentication of plaintexts
- Performance
- Flexibility
- Determinism


## Example using the command-line tool
1. Install the command-line binary
  ```
  go get -u github.com/pivotal-cf-experimental/bletchley/bletchley
  ```

2. Generate a keypair
  ```
  bletchley -o generate -public public_key.pem -private private_key.pem
  ```

3. Encrypt some data using the public key
  ```
  echo "This is a secret message" | bletchley -o encrypt -public public_key.pem > encrypted.json
  ```

4. Decrypt data using the private key
  ```
  cat encrypted.json | bletchley -o decrypt -private private_key.pem
  ```


## Example of use as a libary
See the source code for the CLI tool.
