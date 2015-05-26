#Bletchley
[![Build Status](https://api.travis-ci.org/rosenhouse/bletchley.png?branch=master)](http://travis-ci.org/rosenhouse/bletchley)
[![GoDoc](https://godoc.org/github.com/rosenhouse/bletchley?status.svg)](https://godoc.org/github.com/rosenhouse/bletchley)

Bletchley is a high-level Go library and command-line tool for asymmetric encryption and decryption.

Design goals:
- Easy to use
- Idiot-proof
- Consume and produce standard, open formats

Design non-goals:
- Performance
- Flexibility
- Determinism


## Example using the command-line tool
1. Install the command-line binary
  ```
  go install github.com/rosenhouse/bletchley/bletchley
  ```

2. Generate an RSA keypair
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
