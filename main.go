package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
)

const (
	OperationEncrypt = "encrypt"
	OperationDecrypt = "decrypt"
)

func Fatalf(msg string) {
	os.Stderr.WriteString(msg + "\n")
	os.Exit(1)
}

func main() {
	var password string

	flag.StringVar(&password, "p", "", "password")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage:\n%s <operation>\n  <operation>: %s or %s\n", os.Args[0], OperationEncrypt, OperationDecrypt)
		flag.PrintDefaults()
	}
	flag.Parse()

	if password == "" {
		Fatalf("password required")
	}

	operation := flag.Arg(0)
	if operation != OperationEncrypt && operation != OperationDecrypt {
		Fatalf("specify an operation")
	}

	inputData, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		panic(err)
	}

	outputString := ""

	if operation == OperationEncrypt {
		symCiphertext, err := encrypt(password, inputData)
		if err != nil {
			panic(err)
		}

		outputString = base64.StdEncoding.EncodeToString(symCiphertext)
	}

	if operation == OperationDecrypt {
		ciphertext := make([]byte, base64.StdEncoding.DecodedLen(len(inputData)))
		n, err := base64.StdEncoding.Decode(ciphertext, inputData)
		if err != nil {
			Fatalf("Error during base64 decode of input")
		}

		outputBytes, err := decrypt(password, ciphertext[:n])
		if err != nil {
			Fatalf(err.Error())
		}

		outputString = string(outputBytes)
	}

	fmt.Printf(outputString)
}

func getStreamCipher(password string) (cipher.AEAD, error) {
	hashedPassword := sha256.Sum256([]byte(password))
	aesKey := hashedPassword[:32]

	blockCipher, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(blockCipher)
}

func encrypt(password string, plaintext []byte) ([]byte, error) {
	gcmNonce := make([]byte, 12)
	streamCipher, err := getStreamCipher(password)
	if err != nil {
		return []byte{}, err
	}
	return streamCipher.Seal(nil, gcmNonce, plaintext, nil), nil
}

func decrypt(password string, ciphertext []byte) ([]byte, error) {
	gcmNonce := make([]byte, 12)
	streamCipher, err := getStreamCipher(password)
	if err != nil {
		return []byte{}, err
	}
	return streamCipher.Open(nil, gcmNonce, ciphertext, nil)
}
