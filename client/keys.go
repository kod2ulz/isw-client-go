package client

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"

	"github.com/kod2ulz/interswitch-quickteller/stores"
	"github.com/minio/minio-go/v7"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

const (
	PemKeyContentType = "application/x-pem-file"
)

type Key interface {
	Base64() string
	Public() Key
	Pem() (out []byte)
	// Sign([]byte) error
}

func bytesFromReader(reader io.Reader) (out []byte) {
	buffer := new(bytes.Buffer)
	if _, err := buffer.ReadFrom(reader); err != nil {
		return nil
	}
	return buffer.Bytes()
}

var Keys keyUtils = keyUtils{
	Rsa: rsaUtils{}, Ecdh: ecdhUtils{},
}

type keyUtils struct {
	Rsa  rsaUtils
	Ecdh ecdhUtils
}

type KeyUtil[P any, K any] interface {
	Generate(...P) (K, error)
	DecodePem(io.Reader) (K, error)
}

func loadKey[P any, K Key](ctx context.Context, log *logrus.Entry, keyManager KeyUtil[P, K], store *stores.MinioClient, param P, bucket, keyPath string) (out K, err error) {
	log.Debug("loading from storage")
	if err = store.StreamObject(ctx, bucket, keyPath, func(i int64, s string, reader io.ReadCloser) (e error) {
		defer reader.Close()
		out, e = keyManager.DecodePem(reader)
		return
	}); err == nil {
		log.Info("loaded from storage")
		return
	} else if out, err = keyManager.Generate(param); err != nil {
		err = errors.Wrap(err, "failed to generate rsa key")
		log.WithError(err).Error("failed")
		return
	} else if err = storePemKey(ctx, log, store, out.Pem(), bucket, keyPath); err != nil {
		return out, err
	}
	return
}

func storePemKey(ctx context.Context, log *logrus.Entry, store *stores.MinioClient, key []byte, bucket, keyPath string) (err error) {
	size := int64(len(key))
	opts := minio.PutObjectOptions{
		ContentType: PemKeyContentType,
	}
	if _, err = store.PutObject(ctx, bucket, keyPath, bytes.NewReader(key), size, opts); err != nil {
		err = errors.Wrapf(err, "failed to upload generated %s key to minio", keyPath)
		log.WithError(err).Error("failed")
	}
	return
}

type crypter struct{}

func (crypter) encrypt(plaintext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

	return ciphertext, nil
}

func (crypter) decrypt(ciphertext, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, errors.Errorf("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(ciphertext, ciphertext)

	return ciphertext, nil
}