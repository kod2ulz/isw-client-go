package client

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"hash"
	"io"

	"github.com/pkg/errors"
)

const (
	RsaMinBits        = 2048
	RsaPrivateKeyType = "RSA PRIVATE KEY"
	RsaPublicKeyType  = "RSA PUBLIC KEY"
)

type RsaPrivateKey struct {
	val *rsa.PrivateKey
}

func (k *RsaPrivateKey) Public() Key {
	return &RsaPublicKey{private: k}
}

func (k *RsaPrivateKey) Base64() string {
	byts := x509.MarshalPKCS1PrivateKey(k.val)
	return base64.StdEncoding.EncodeToString(byts)
}

func (k *RsaPrivateKey) Pem() (out []byte) {
	pemBytes := new(bytes.Buffer)
	if err := pem.Encode(pemBytes, &pem.Block{
		Bytes: x509.MarshalPKCS1PrivateKey(k.val),
		Type:  RsaPrivateKeyType,
	}); err != nil {
		return nil
	}
	return pemBytes.Bytes()
}

func (k *RsaPrivateKey) Sign(message []byte) (out []byte, err error) {
	hashed := sha256.Sum256(message)
	return rsa.SignPKCS1v15(rand.Reader, k.val, crypto.SHA256, hashed[:])
}

func (k *RsaPrivateKey) Verify(message, signature []byte) (err error) {
	hashed := sha256.Sum256(message)
	return rsa.VerifyPKCS1v15(&k.val.PublicKey, crypto.SHA256, hashed[:], signature)
}

func (k *RsaPrivateKey) Encrypt(_hash hash.Hash, message []byte) (out []byte, err error) {
	return out, errors.Errorf("not applicable")
}

func (k *RsaPrivateKey) Decrypt(_hash hash.Hash, message []byte) (out []byte, err error) {
	return rsa.DecryptOAEP(_hash, rand.Reader, k.val, message, nil)
}

type RsaPublicKey struct {
	private *RsaPrivateKey
}

func (k *RsaPublicKey) Pem() (out []byte) {
	pemBytes := new(bytes.Buffer)
	if err := pem.Encode(pemBytes, &pem.Block{
		Bytes: x509.MarshalPKCS1PublicKey(&k.private.val.PublicKey),
		Type:  RsaPublicKeyType,
	}); err != nil {
		return nil
	}
	return pemBytes.Bytes()
}

func (k *RsaPublicKey) Base64() string {
	byts := x509.MarshalPKCS1PublicKey(&k.private.val.PublicKey)
	return base64.StdEncoding.EncodeToString(byts)
}

func (k *RsaPublicKey) Public() Key {
	return k
}

func (k *RsaPublicKey) Sign(_hash any, message []byte) (out []byte, err error) {
	return out, errors.Errorf("not applicable")
}


func (k *RsaPublicKey) Verify(message, signature []byte) (err error) {
	return errors.Errorf("not applicable")
}

func (k *RsaPublicKey) Encrypt(_hash hash.Hash, message []byte) (out []byte, err error) {
	return rsa.EncryptOAEP(_hash, rand.Reader, &k.private.val.PublicKey, message, nil)
}

func (k *RsaPublicKey) Decrypt(_hash hash.Hash, message []byte) (out []byte, err error) {
	return out, errors.Errorf("not applicable")
}

type rsaUtils struct{}

func (rsaUtils) Generate(bitSize ...int) (out *RsaPrivateKey, err error) {
	_bitSize := RsaMinBits
	if len(bitSize) > 0 {
		if bitSize[0] < RsaMinBits {
			return nil, errors.Errorf("inadequate rsa bit size %d", bitSize)
		} else {
			_bitSize = bitSize[0]
		}
	}
	out = &RsaPrivateKey{}
	out.val, err = rsa.GenerateKey(rand.Reader, _bitSize)
	return
}

func (rsaUtils) DecodePem(reader io.Reader) (out *RsaPrivateKey, err error) {
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
