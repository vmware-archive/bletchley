#bletchley

Bletchley is a Go library and command-line tool for asymmetric encryption and decryption.

Design goals:
- Easy to use
- Idiot-proof
- Consume and produce standard, open formats

Design non-goals:
- Performance
- Flexibility
- Determinism


## Example using the command-line tool
1. Compile the binary
```
go install
```

2. Generate an RSA keypair
```
openssl genrsa -out private_key.pem 4096
```

3. Extract the public key to a separate file
```
openssl genrsa -out private_key.pem 4096
```

4. Encrypt some data using the public key
```
echo "This is a secret message" | bletchley -o encrypt -k public_key.pem > encrypted.json
```

5. Decrypt data using the private key
```
cat encrypted.json | bletchley -o decrypt -k private_key.pem
```

