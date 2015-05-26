package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/rosenhouse/bletchley"
)

const (
	operationEncrypt  = "encrypt"
	operationDecrypt  = "decrypt"
	operationGenerate = "generate"
)

var (
	operation      string
	privateKeyPath string
	publicKeyPath  string
)

func Fatalf(format string, a ...interface{}) {
	os.Stderr.WriteString(fmt.Sprintf(format, a) + "\n")
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
		Fatalf("provide input data on stdin")
	}

	inputData, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		panic(err)
	}

	return inputData
}

func main() {
	allowedOperations := []string{operationEncrypt, operationDecrypt, operationGenerate}

	flag.StringVar(&operation, "o", "",
		fmt.Sprintf("operation: one of %+v", allowedOperations))
	flag.StringVar(&privateKeyPath, "private", "", "path to private key")
	flag.StringVar(&publicKeyPath, "public", "", "path to public key")
	flag.Parse()

	if operation != operationEncrypt && operation != operationDecrypt && operation != operationGenerate {
		Fatalf("Expected operation to be one of %s", allowedOperations)
	}

	if operation == operationEncrypt {
		inputData := readInputBytes()
		keyBytes := readKeyBytes("public", publicKeyPath)

		publicKey, err := bletchley.PublicKeyFromPEM(keyBytes)
		if err != nil {
			Fatalf(err.Error())
		}

		encrypted, err := bletchley.Encrypt(publicKey, inputData)
		if err != nil {
			Fatalf(err.Error())
		}

		outputBytes, err := json.Marshal(encrypted)
		if err != nil {
			Fatalf(err.Error())
		}

		fmt.Print(string(outputBytes))

	} else if operation == operationDecrypt {
		inputData := readInputBytes()
		keyBytes := readKeyBytes("private", privateKeyPath)

		privateKey, err := bletchley.PrivateKeyFromPEM(keyBytes)
		if err != nil {
			Fatalf(err.Error())
		}

		var encrypted bletchley.EncryptedMessage
		err = json.Unmarshal(inputData, &encrypted)
		if err != nil {
			Fatalf("Expected JSON input: " + err.Error())
		}

		plaintext, err := bletchley.Decrypt(privateKey, encrypted)
		if err != nil {
			Fatalf("Failed to decrypt: " + err.Error())
		}

		fmt.Print(string(plaintext))

	} else if operation == operationGenerate {

		privateKey, publicKey, err := bletchley.Generate()
		if err != nil {
			Fatalf(err.Error())
		}

		privateKeyPEM := bletchley.PrivateKeyToPEM(privateKey)
		publicKeyPEM, err := bletchley.PublicKeyToPEM(publicKey)
		if err != nil {
			Fatalf(err.Error())
		}

		if privateKeyPath == "" {
			fmt.Print(string(privateKeyPEM))
			return
		}

		err = ioutil.WriteFile(privateKeyPath, privateKeyPEM, os.FileMode(0600))
		if err != nil {
			Fatalf("Error writing private key file")
		}

		if publicKeyPath != "" {
			err = ioutil.WriteFile(publicKeyPath, publicKeyPEM, os.FileMode(0644))
			if err != nil {
				Fatalf("Error writing private key file")
			}
		}

		return
	}
}
