#bletchley

Bletchley is a Go library and command-line tool for asymmetric encryption and decryption.

Design goals:
- Usable and safe for crypto-novices
- Serialize to / from standard, open formats

Non-goals:
- Performance
- Flexibility
- Deterministic encryption


## Example
1. Generate an RSA keypair
```
openssl genrsa -out private_key.pem 4096
```

2. Extract the public key to a separate file
```
openssl genrsa -out private_key.pem 4096
```

3. Encrypt some data using the public key
```
echo "This is a secret message" | ./bletchley -o encrypt -k public_key.pem > encrypted.json
```

4. Decrypt data using the private key
```
cat encrypted.json | ./bletchley -o decrypt -k private_key.pem
```

