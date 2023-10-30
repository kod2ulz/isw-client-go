package client

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
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
	crypter
	val    *ecdsa.PrivateKey
	theirs *ecdsa.PublicKey
	public *EcdhPublicKey
	secret []byte
}

func (k *EcdhPrivateKey) init() (err error) {
	k.public = &EcdhPublicKey{
		private: k, public: &k.val.PublicKey,
	}
	return nil
}

func (k *EcdhPrivateKey) Public() Key {
	return k.public
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

func (k *EcdhPrivateKey) Sign(message []byte) (out []byte, err error) {
	hashed := sha256.Sum256(message)
	// return k.val.Sign(rand.Reader, message, nil)
	return ecdsa.SignASN1(rand.Reader, k.val, hashed[:])
}

func (k *EcdhPrivateKey) Verify(message, signature []byte) (err error) {
	hashed := sha256.Sum256(message)
	if !ecdsa.VerifyASN1(&k.val.PublicKey, hashed[:], signature) {
		err = errors.Errorf("signature invalid for this message")
	}
	return
}

func (k *EcdhPrivateKey) SetTheirKey(publicKey *EcdhPublicKey) (err error) {
	k.theirs = publicKey.public
	return
}

func (k *EcdhPrivateKey) SharedSecret() ([]byte, error) {
	if len(k.secret) > 0 {
		return k.secret, nil
	} else if k.theirs == nil {
		return nil, errors.Errorf("their public key required to generate shared secret. call %T.SetTheirKey(k)", k)
	}
	x, _ := k.theirs.Curve.ScalarMult(k.theirs.X, k.theirs.Y, k.val.D.Bytes())
	k.secret = x.Bytes()
	return k.secret, nil
}

func (k *EcdhPrivateKey) Encrypt(message []byte) (out []byte, err error) {
	var secret []byte
	if secret, err = k.SharedSecret(); err != nil {
		return
	}
	return k.encrypt(message, secret)
}

func (k *EcdhPrivateKey) Decrypt(cipher []byte) (out []byte, err error) {
	var secret []byte
	if secret, err = k.SharedSecret(); err != nil {
		return
	}
	return k.decrypt(cipher, secret)
}

type EcdhPublicKey struct {
	private *EcdhPrivateKey
	public  *ecdsa.PublicKey
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

func (k *EcdhPublicKey) Sign(message []byte) (out []byte, err error) {
	return out, errors.Errorf("not applicable")
}

func (k *EcdhPublicKey) Verify(message, signature []byte) (err error) {
	return errors.Errorf("not applicable")
}

func (k *EcdhPublicKey) Encrypt(message []byte) (out []byte, err error) {
	return out, errors.Errorf("not applicable")
}

func (k *EcdhPublicKey) Decrypt(message []byte) (out []byte, err error) {
	return out, errors.Errorf("not applicable")
}

type ecdhUtils struct{}

func (ecdhUtils) Generate(curve ...elliptic.Curve) (out *EcdhPrivateKey, err error) {
	_curve := EcdhCurve
	if len(curve) > 0 && curve[0] != nil {
		_curve = curve[0]
	}
	out = &EcdhPrivateKey{}
	out.val, err = ecdsa.GenerateKey(_curve, rand.Reader)
	out.init()
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
	out = &EcdhPrivateKey{val: privateKey}
	out.init()
	return
}
