package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/pivotal-cf-experimental/bletchley"
)

const (
	operationEncrypt  = "encrypt"
	operationDecrypt  = "decrypt"
	operationGenerate = "generate"
)

var (
	cipher bletchley.Cipher

	operation      string
	privateKeyPath string
	publicKeyPath  string

	allowedOperations []string = []string{operationEncrypt, operationDecrypt, operationGenerate}
)

func init() {
	flag.StringVar(&operation, "o", "", fmt.Sprintf("operation: one of %+v", allowedOperations))
	flag.StringVar(&privateKeyPath, "private", "", "path to private key")
	flag.StringVar(&publicKeyPath, "public", "", "path to public key")
}

func Fatal(msg string) {
	Fatalf("%s", msg)
}

func Fatalf(format string, a ...interface{}) {
	os.Stderr.WriteString(fmt.Sprintf(format, a...) + "\n")
	os.Exit(1)
}

func readKeyBytes(keyType, keyPath string) []byte {
	if keyPath == "" {
		flag.Usage()
		Fatalf("Expected path to the %s key file", keyType)
	}

	keyBytes, err := ioutil.ReadFile(keyPath)
	if err != nil {
		Fatalf("Error reading %s key file: %s", keyType, keyPath)
	}

	return keyBytes
}

func readInputBytes() []byte {
	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		Fatal("provide input data on stdin")
	}

	inputData, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		panic(err)
	}

	return inputData
}

func encrypt(plaintext, keyBytes []byte) ([]byte, error) {
	publicKey, err := cipher.PEMToPublicKey(keyBytes)
	if err != nil {
		return []byte{}, err
	}

	encrypted, err := cipher.Encrypt(publicKey, plaintext)
	if err != nil {
		return []byte{}, err
	}

	return json.Marshal(encrypted)
}

func decrypt(ciphertext, keyBytes []byte) ([]byte, error) {
	privateKey, err := cipher.PEMToPrivateKey(keyBytes)
	if err != nil {
		return []byte{}, err
	}

	var encrypted bletchley.EncryptedMessage
	err = json.Unmarshal(ciphertext, &encrypted)
	if err != nil {
		return []byte{}, fmt.Errorf("Expected JSON input: " + err.Error())
	}

	return cipher.Decrypt(privateKey, encrypted)
}

func generate() ([]byte, []byte, error) {
	privateKey, publicKey, err := cipher.Generate()
	if err != nil {
		return []byte{}, []byte{}, err
	}

	privateKeyPEM := cipher.PrivateKeyToPEM(privateKey)
	publicKeyPEM, err := cipher.PublicKeyToPEM(publicKey)

	return publicKeyPEM, privateKeyPEM, err
}

func main() {
	flag.Parse()

	switch operation {
	case operationEncrypt:
		plaintext := readInputBytes()
		publicKeyBytes := readKeyBytes("public", publicKeyPath)
		ciphertext, err := encrypt(plaintext, publicKeyBytes)
		if err != nil {
			Fatal(err.Error())
		}
		fmt.Print(string(ciphertext))

	case operationDecrypt:
		ciphertext := readInputBytes()
		privateKeyBytes := readKeyBytes("private", privateKeyPath)
		plaintext, err := decrypt(ciphertext, privateKeyBytes)
		if err != nil {
			Fatal(err.Error())
		}
		fmt.Print(string(plaintext))

	case operationGenerate:
		publicKeyPEM, privateKeyPEM, err := generate()
		if err != nil {
			Fatal(err.Error())
		}

		if privateKeyPath == "" {
			fmt.Print(string(privateKeyPEM))
			return
		}

		err = ioutil.WriteFile(privateKeyPath, privateKeyPEM, os.FileMode(0600))
		if err != nil {
			Fatalf("Error writing private key file: %s", err)
		}

		if publicKeyPath != "" {
			err = ioutil.WriteFile(publicKeyPath, publicKeyPEM, os.FileMode(0644))
			if err != nil {
				Fatalf("Error writing private key file: %s", err)
			}
		}

	default:
		Fatalf("Expected operation to be one of %s", allowedOperations)
	}
}
