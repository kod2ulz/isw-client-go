package client

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"

	"github.com/pkg/errors"
)

const (
	RsaMinBits        = 2048
	RsaPrivateKeyType = "RSA PRIVATE KEY"
)

type RsaPrivateKey struct {
	val *rsa.PrivateKey
}

func (k *RsaPrivateKey) Public() crypto.PublicKey {
	return k.val.Public()
}

func (k *RsaPrivateKey) PublicBase64() string {
	byts := x509.MarshalPKCS1PublicKey(&k.val.PublicKey)
	return base64.StdEncoding.EncodeToString(byts)
}

func (k *RsaPrivateKey) Pem() (out []byte) {
	pemBytes := &bytes.Buffer{}
	if err := pem.Encode(pemBytes, &pem.Block{
		Bytes: x509.MarshalPKCS1PrivateKey(k.val),
		Type:  RsaPrivateKeyType,
	}); err != nil {
		return nil
	}
	return pemBytes.Bytes()
}

func GenerateRsaKey(bitSize int) (out *RsaPrivateKey, err error) {
	if bitSize < RsaMinBits {
		return nil, errors.Errorf("insufficient rsa bit size %d", bitSize)
	}
	out = &RsaPrivateKey{}
	out.val, err = rsa.GenerateKey(rand.Reader, bitSize)
	return
}

func RsaPemDecode(reader io.Reader) (out *RsaPrivateKey, err error) {
	var ok bool
	var privPemBytes []byte
	var parsedKey interface{}
	var privateKey *rsa.PrivateKey
	privPem, _ := pem.Decode(bytesFromReader(reader))
	if privPem.Type != RsaPrivateKeyType {
		return nil, errors.Errorf("RSA private key is of the wrong type :%s", privPem.Type)
	}
	privPemBytes = privPem.Bytes
	if parsedKey, err = x509.ParsePKCS1PrivateKey(privPemBytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(privPemBytes); err != nil {
			return nil, errors.Wrapf(err, "Unable to parse RSA private key")
		}
	}
	if privateKey, ok = parsedKey.(*rsa.PrivateKey); !ok {
		return nil, errors.Errorf("Unable to parse RSA private key")
	}
	return &RsaPrivateKey{val: privateKey}, nil
}
