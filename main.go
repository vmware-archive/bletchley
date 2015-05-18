package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
)

const (
	operationEncrypt = "encrypt"
	operationDecrypt = "decrypt"
)

func Fatalf(msg string) {
	os.Stderr.WriteString(msg + "\n")
	os.Exit(1)
}

type encryptedFormat struct {
	Ciphertext   []byte `json:"ciphertext"`
	Nonce        []byte `json:"nonce"`
	EncryptedKey []byte `json:"encrypted_key"`
}

func main() {
	var operation string
	var keyPath string

	flag.StringVar(&operation, "o", "", fmt.Sprintf("operation: '%s' or '%s'", operationEncrypt, operationDecrypt))
	flag.StringVar(&keyPath, "k", "", "path to public or private key")
	flag.Parse()

	if keyPath == "" {
		Fatalf("Specify the path to the key file")
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

		asymmetricStep, err := loadAsymmetricEncrypter(keyPath)
		if err != nil {
			panic(err)
		}

		symmetricStep, err := generateSymmetric()
		if err != nil {
			panic(err)
		}

		symCiphertext := symmetricStep.encrypt(inputData)

		encryptedKey, err := asymmetricStep.encrypt(symmetricStep.aesKey)
		if err != nil {
			panic(err)
		}

		outputBytes, err := json.Marshal(encryptedFormat{
			Ciphertext:   symCiphertext,
			EncryptedKey: encryptedKey,
			Nonce:        symmetricStep.gcmNonce,
		})
		if err != nil {
			panic(err)
		}

		outputString = string(outputBytes)
	} else if operation == operationDecrypt {

		asymmetricStep, err := loadAsymmetricDecrypter(keyPath)
		if err != nil {
			panic(err)
		}

		var enc encryptedFormat
		err = json.Unmarshal(inputData, &enc)
		if err != nil {
			Fatalf("Expected JSON input: " + err.Error())
		}

		aesKey, err := asymmetricStep.decrypt(enc.EncryptedKey)
		if err != nil {
			Fatalf("RSA decryption: " + err.Error())
		}

		symmetricStep, err := loadSymmetric(aesKey, enc.Nonce)
		if err != nil {
			Fatalf("GCM AES setup: " + err.Error())
		}

		plaintext, err := symmetricStep.decrypt(enc.Ciphertext)
		if err != nil {
			Fatalf("GCM AES decryption: " + err.Error())
		}

		outputString = string(plaintext)
	}

	fmt.Printf(outputString)
}
