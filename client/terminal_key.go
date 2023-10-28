package client

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
)

type TerminalKey string

func (k TerminalKey) Bytes() []byte {
	return []byte(k)
}

func (k TerminalKey) Sign(message string) (out string, err error) {
	block, err := aes.NewCipher(k.Bytes())
	if err != nil {
		return "", err
	}
	
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}

	msgBytes := []byte(message)
	msgBytes = k.pkcs7Pad(msgBytes, aes.BlockSize)

	ciphertext := make([]byte, len(iv)+len(msgBytes))
	copy(ciphertext[:aes.BlockSize], iv)

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext[aes.BlockSize:], msgBytes)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func (k TerminalKey) pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padtext...)
}
