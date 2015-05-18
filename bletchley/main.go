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
	operationEncrypt = "encrypt"
	operationDecrypt = "decrypt"
)

func Fatalf(msg string) {
	os.Stderr.WriteString(msg + "\n")
	os.Exit(1)
}

func main() {
	var operation string
	var keyPath string

	flag.StringVar(&operation, "o", "", fmt.Sprintf("operation: '%s' or '%s'", operationEncrypt, operationDecrypt))
	flag.StringVar(&keyPath, "k", "", "path to public or private key")
	flag.Parse()

	if keyPath == "" {
		flag.Usage()
		Fatalf("Specify the path to the key file")
	}

	keyBytes, err := ioutil.ReadFile(keyPath)
	if err != nil {
		Fatalf("Error reading key file: " + err.Error())
	}

	if operation != operationEncrypt && operation != operationDecrypt {
		Fatalf(fmt.Sprintf("Expected operation to be either '%s' or '%s'", operationEncrypt, operationDecrypt))
	}

	stat, _ := os.Stdin.Stat()
	if (stat.Mode() & os.ModeCharDevice) != 0 {
		Fatalf("provide input data on stdin")
	}

	inputData, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		panic(err)
	}

	outputString := ""

	if operation == operationEncrypt {
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

		outputString = string(outputBytes)

	} else if operation == operationDecrypt {
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

		outputString = string(plaintext)
	}

	fmt.Printf(outputString)
}
