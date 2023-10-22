package client

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"

	"github.com/pkg/errors"
)

var (
	EcdhCurve          = elliptic.P256()
	EcdhPrivateKeyType = "EC PRIVATE KEY"
	EcdhPublicKeyType  = "PUBLIC KEY"
)

type EcdhPrivateKey struct {
	val *ecdsa.PrivateKey
}

func (k *EcdhPrivateKey) Public() Key {
	return &EcdhPublicKey{private: k}
}

func (k *EcdhPrivateKey) PublicBase64() string {
	var pubkey *ecdsa.PublicKey = &k.val.PublicKey
	byts := elliptic.Marshal(pubkey, pubkey.X, pubkey.Y)
	return base64.StdEncoding.EncodeToString(byts)
}

func (k *EcdhPrivateKey) Base64() (out string) {
	if ky, err := k.val.ECDH(); err == nil {
		return base64.StdEncoding.EncodeToString(ky.Bytes())
	}
	return
}

func (k *EcdhPrivateKey) Pem() (out []byte) {
	data, err := x509.MarshalECPrivateKey(k.val)
	if err != nil {
		return
	}
	pemBytes := new(bytes.Buffer)
	if err = pem.Encode(pemBytes, &pem.Block{
		Type: EcdhPrivateKeyType, Bytes: data,
	}); err != nil {
		return nil
	}
	return pemBytes.Bytes()
}

type EcdhPublicKey struct {
	private *EcdhPrivateKey
}

func (k *EcdhPublicKey) Pem() (out []byte) {
	pemBytes := new(bytes.Buffer)
	if data, err := x509.MarshalPKIXPublicKey(k.private.val.PublicKey); err != nil {
		return
	} else if err := pem.Encode(pemBytes, &pem.Block{
		Bytes: data,
		Type:  EcdhPublicKeyType,
	}); err != nil {
		return nil
	}
	return pemBytes.Bytes()
}

// func (k *EcdhPublicKey) Base64() (out string) {
// 	if data, err := x509.MarshalPKIXPublicKey(k.private.val.PublicKey); err != nil {
// 		return base64.StdEncoding.EncodeToString(data)
// 	}
// 	return
// }

func (k *EcdhPublicKey) Base64() (out string) {
	var pubkey *ecdsa.PublicKey = &k.private.val.PublicKey
	byts := elliptic.Marshal(pubkey, pubkey.X, pubkey.Y)
	return base64.StdEncoding.EncodeToString(byts)
}

func (k *EcdhPublicKey) Public() Key {
	return k
}

type ecdhUtils struct{}

func (ecdhUtils) Generate(curve ...elliptic.Curve) (out *EcdhPrivateKey, err error) {
	_curve := EcdhCurve
	if len(curve) > 0 && curve[0] != nil {
		_curve = curve[0]
	}
	out = &EcdhPrivateKey{}
	out.val, err = ecdsa.GenerateKey(_curve, rand.Reader)
	return
}

func (ecdhUtils) DecodePem(reader io.Reader) (out *EcdhPrivateKey, err error) {
	var ok bool
	var parsedKey interface{}
	var privateKey *ecdsa.PrivateKey
	privPem, _ := pem.Decode(bytesFromReader(reader))
	if privPem.Type != EcdhPrivateKeyType {
		return nil, errors.Errorf("ECDH private key is of the wrong type :%s", privPem.Type)
	} else if parsedKey, err = x509.ParseECPrivateKey(privPem.Bytes); err != nil {
		return nil, errors.Wrapf(err, "Unable to parse ECDH private key")
	} else if privateKey, ok = parsedKey.(*ecdsa.PrivateKey); !ok {
		return nil, errors.Errorf("Unable to parse ECDH private key")
	}
	return &EcdhPrivateKey{val: privateKey}, nil
}
