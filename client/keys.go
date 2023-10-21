package client

import (
	"bytes"
	"crypto"
	"io"
)

type Key interface {
	ToBase64() string
	Public() crypto.PublicKey
	Pem() (out []byte)
}

func bytesFromReader(reader io.Reader) (out []byte) {
	buffer := new(bytes.Buffer)
	if _, err := buffer.ReadFrom(reader); err != nil {
		return nil
	}
	return buffer.Bytes()
}
