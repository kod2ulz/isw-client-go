package client_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/kod2ulz/interswitch-quickteller/client"
)

var _ = Describe("Client Keys", func() {

	Context("RSA Key", func() {

		var err error
		var publicKey *client.RsaPublicKey
		var privateKey *client.RsaPrivateKey

		BeforeEach(func() {
			privateKey, err = client.Keys.Rsa.Generate()
			publicKey = privateKey.Public().(*client.RsaPublicKey)
		})

		It("Can Generate Private Key", func() {
			Expect(err).To(BeNil())
			Expect(privateKey).NotTo(BeNil())
		})

		It("Can Generate Public Key from the private key", func() {
			Expect(err).To(BeNil())
			Expect(privateKey.Public()).NotTo(BeNil())
		})

		It("Can Encode Public Key as base64", func() {
			Expect(err).To(BeNil())
			publicBase64 := publicKey.Base64()
			_, err = base64.StdEncoding.DecodeString(publicBase64)
			Expect(err).To(BeNil())
		})

		It("can sign message with the private key", func() {
			Expect(err).To(BeNil())
			var signature []byte
			message := []byte("i am groot")

			signature, err = privateKey.Sign(message)
			Expect(err).To(BeNil())
			Expect(signature).ToNot(Equal(message))
			Expect(privateKey.Verify(message, signature)).To(BeNil())
		})

		It("can generate pem from private key", func() {
			Expect(err).To(BeNil())
			var outPemKey *client.RsaPrivateKey

			pemKey := privateKey.Pem()
			outPemKey, err = client.Keys.Rsa.DecodePem(bytes.NewReader(pemKey))

			Expect(err).To(BeNil())
			Expect(outPemKey).To(Equal(privateKey))
		})

		It("can decode message encrypted with public key using private key", func() {
			Expect(err).To(BeNil())

			var hash = sha256.New()
			var encoded, decoded []byte
			var message = []byte("i am still groot")

			encoded, err = publicKey.Encrypt(hash, message)
			Expect(err).To(BeNil())

			decoded, err = privateKey.Decrypt(hash, encoded)
			Expect(err).To(BeNil())

			Expect(encoded).ToNot(Equal(decoded))
			Expect(decoded).To(Equal(message))
		})

	})

	Context("ECDH Key", func() {

		var err error
		var publicKey *client.EcdhPublicKey
		var privateKey *client.EcdhPrivateKey

		BeforeEach(func() {
			privateKey, err = client.Keys.Ecdh.Generate()
			publicKey = privateKey.Public().(*client.EcdhPublicKey)
		})

		It("Can Generate Private Key", func() {
			Expect(err).To(BeNil())
			Expect(privateKey).NotTo(BeNil())
		})

		It("Can Generate Public Key from the private key", func() {
			Expect(err).To(BeNil())
			Expect(privateKey.Public()).NotTo(BeNil())
		})

		It("Can Encode Public Key as base64", func() {
			Expect(err).To(BeNil())
			publicBase64 := publicKey.Base64()
			_, err = base64.StdEncoding.DecodeString(publicBase64)
			Expect(err).To(BeNil())
		})

		It("can sign message with the private key", func() {
			Expect(err).To(BeNil())
			var signature []byte
			message := []byte("i am groot")

			signature, err = privateKey.Sign(message)
			Expect(err).To(BeNil())
			Expect(signature).ToNot(Equal(message))
			Expect(privateKey.Verify(message, signature)).To(BeNil())
		})

		It("can generate pem from private key", func() {
			Expect(err).To(BeNil())
			var outPemKey *client.EcdhPrivateKey

			pemKey := privateKey.Pem()
			outPemKey, err = client.Keys.Ecdh.DecodePem(bytes.NewReader(pemKey))

			Expect(err).To(BeNil())
			Expect(outPemKey).To(Equal(privateKey))
		})

		It("can decode message encrypted with our private key using their private key", func() {
			Expect(err).To(BeNil())

			var encoded, decoded []byte
			var message = []byte("i am still groot")

			var theirPublicKey *client.EcdhPublicKey
			var theirPrivateKey *client.EcdhPrivateKey

			theirPrivateKey, err = client.Keys.Ecdh.Generate()
			Expect(err).To(BeNil())
			theirPublicKey = theirPrivateKey.Public().(*client.EcdhPublicKey)

			privateKey.SetTheirKey(theirPublicKey)
			theirPrivateKey.SetTheirKey(publicKey)

			encoded, err = privateKey.Encrypt(message)
			Expect(err).To(BeNil())

			decoded, err = theirPrivateKey.Decrypt(encoded)
			Expect(err).To(BeNil())

			Expect(encoded).ToNot(Equal(decoded))
			Expect(decoded).To(Equal(message))
		})

	})

})
