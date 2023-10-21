package client

import (
	"bytes"
	"crypto"
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
)

type EcdhPrivateKey struct {
	val *ecdsa.PrivateKey
}

func (k *EcdhPrivateKey) Public() crypto.PublicKey {
	return k.val.Public()
}

func (k *EcdhPrivateKey) PublicBase64() string {
	var pubkey *ecdsa.PublicKey = &k.val.PublicKey
	byts := elliptic.Marshal(pubkey, pubkey.X, pubkey.Y)
	return base64.StdEncoding.EncodeToString(byts)
}

func (k *EcdhPrivateKey) Pem() (out []byte) {
	data, err := x509.MarshalECPrivateKey(k.val)
	if err != nil {
		return
	}
	pemBytes := &bytes.Buffer{}
	if err = pem.Encode(pemBytes, &pem.Block{
		Type: EcdhPrivateKeyType, Bytes: data,
	}); err != nil {
		return nil
	}
	return pemBytes.Bytes()
}

func GenerateEcdhKey(c ...elliptic.Curve) (out *EcdhPrivateKey, err error) {
	curve := EcdhCurve
	if len(c) > 0 && c[0] != nil {
		curve = c[0]
	}
	out = &EcdhPrivateKey{}
	out.val, err = ecdsa.GenerateKey(curve, rand.Reader)
	return
}

func EcdhPemDecode(reader io.Reader) (out *EcdhPrivateKey, err error) {
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
