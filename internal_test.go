package sshsig

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"
)

// This file contains "white box" tests that test certain things that are not
// exposed through the public API, but are still important to test.

func TestParseSignature(t *testing.T) {
	t.Run("invalid blob data", func(t *testing.T) {
		got, err := ParseSignature(blob{}.Marshal())
		assert.ErrorIs(t, err, ErrUnsupportedSignatureVersion)
		assert.Nil(t, got)
	})

	t.Run("invalid signature", func(t *testing.T) {
		got, err := ParseSignature(blob{
			Version:       sigVersion,
			Signature:     "invalid",
			HashAlgorithm: HashSHA256.String(),
		}.Marshal())
		assert.ErrorContains(t, err, "ssh: unmarshal error for field Format of type Signature")
		assert.Nil(t, got)
	})

	t.Run("invalid private key", func(t *testing.T) {
		got, err := ParseSignature(blob{
			Version:       sigVersion,
			Signature:     string(ssh.Marshal(&ssh.Signature{})),
			HashAlgorithm: HashSHA256.String(),
		}.Marshal())
		assert.ErrorContains(t, err, "ssh: short read")
		assert.Nil(t, got)
	})

	t.Run("invalid RSA signature", func(t *testing.T) {
		pk, err := rsa.GenerateKey(rand.Reader, 1024)
		assert.NoError(t, err)

		pub, err := ssh.NewPublicKey(&pk.PublicKey)
		assert.NoError(t, err)

		got, err := ParseSignature(blob{
			Version:       sigVersion,
			PublicKey:     string(pub.Marshal()),
			HashAlgorithm: HashSHA256.String(),
			Signature: string(ssh.Marshal(&ssh.Signature{
				Format: ssh.KeyAlgoRSA,
			})),
		}.Marshal())
		assert.ErrorContains(t, err, `invalid signature format "ssh-rsa"`)
		assert.Nil(t, got)
	})
}

func TestVerify_WithoutNamespace(t *testing.T) {
	testMessage := []byte("And now for something completely different.")

	// Deliberately generate a signature with an empty namespace,
	// which is not allowed through the public API.
	algo := HashSHA256
	h := algo.Hash()
	h.Write(testMessage)
	mh := h.Sum(nil)

	_, cSigner, err := ed25519.GenerateKey(rand.Reader)
	assert.NoError(t, err)

	signer, err := ssh.NewSignerFromKey(cSigner)
	assert.NoError(t, err)

	sd := signedData{
		Namespace:     "",
		HashAlgorithm: algo.String(),
		Hash:          string(mh),
	}

	sig, err := signer.Sign(rand.Reader, sd.Marshal())
	assert.NoError(t, err)

	// Verify the namespace-less signature.
	err = Verify(bytes.NewReader(testMessage), &Signature{
		PublicKey: signer.PublicKey(),
		Signature: sig,
	}, signer.PublicKey(), algo, sd.Namespace)
	assert.NoError(t, err)
}
