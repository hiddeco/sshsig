package sshsig_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"

	"github.com/hiddeco/sshsig"
)

func TestSign(t *testing.T) {
	t.Run("empty namespace", func(t *testing.T) {
		got, err := sshsig.Sign(nil, nil, sshsig.HashSHA256, "")
		assert.ErrorIs(t, err, sshsig.ErrMissingNamespace)
		assert.Nil(t, got)
	})

	t.Run("unsupported hash", func(t *testing.T) {
		got, err := sshsig.Sign(nil, nil, "invalid", "test")
		assert.ErrorIs(t, err, sshsig.ErrUnsupportedHashAlgorithm)
		assert.Nil(t, got)
	})

	t.Run("message read error", func(t *testing.T) {
		mockErr := errors.New("read error")
		got, err := sshsig.Sign(iotest.ErrReader(mockErr), nil, sshsig.HashSHA256, "test")
		assert.ErrorIs(t, err, mockErr)
		assert.Nil(t, got)
	})
}

func TestSignVerify(t *testing.T) {
	var (
		testNamespace = "file"
		testMessage   = []byte(`The problem with most conspiracy theories is that they seem to believe that
for a group of people to behave in a way detrimental to the common good
requires intent.`)
	)

	keyTypes := []struct {
		name     string
		generate func() (crypto.PublicKey, crypto.Signer, error)
	}{
		{"ed25519", func() (crypto.PublicKey, crypto.Signer, error) {
			return ed25519.GenerateKey(rand.Reader)
		}},
		{"ecdsa-p256", func() (crypto.PublicKey, crypto.Signer, error) {
			pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				return nil, nil, err
			}
			return &pk.PublicKey, pk, nil
		}},
		{"ecdsa-p384", func() (crypto.PublicKey, crypto.Signer, error) {
			pk, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			if err != nil {
				return nil, nil, err
			}
			return &pk.PublicKey, pk, nil
		}},
		{"ecdsa-p521", func() (crypto.PublicKey, crypto.Signer, error) {
			pk, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
			if err != nil {
				return nil, nil, err
			}
			return &pk.PublicKey, pk, nil
		}},
		{"rsa-1024", func() (crypto.PublicKey, crypto.Signer, error) {
			pk, err := rsa.GenerateKey(rand.Reader, 1024)
			if err != nil {
				return nil, nil, err
			}
			return &pk.PublicKey, pk, nil
		}},
		{"rsa-2048", func() (crypto.PublicKey, crypto.Signer, error) {
			pk, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				return nil, nil, err
			}
			return &pk.PublicKey, pk, nil
		}},
		{"rsa-3072", func() (crypto.PublicKey, crypto.Signer, error) {
			pk, err := rsa.GenerateKey(rand.Reader, 3072)
			if err != nil {
				return nil, nil, err
			}
			return &pk.PublicKey, pk, nil
		}},
		// rsa-4096 and rsa-8192 are technically also possibilities, but take a long time to generate...
	}

	for _, a := range sshsig.SupportedHashAlgorithms() {
		algo := a
		for _, k := range keyTypes {
			key := k
			t.Run(fmt.Sprintf("%s-%s", algo, key.name), func(t *testing.T) {
				// Make test go brrrr...
				t.Parallel()

				// Generate a key to sign with.
				cPub, cSigner, err := key.generate()
				assert.NoError(t, err)
				pub, err := ssh.NewPublicKey(cPub)
				assert.NoError(t, err)
				signer, err := ssh.NewSignerFromSigner(cSigner)
				assert.NoError(t, err)

				// Sign with the first key.
				sig, err := sshsig.Sign(bytes.NewReader(testMessage), signer, algo, testNamespace)
				assert.NoError(t, err)

				// Confirm signature algorithm overwrite for RSA.
				if pub.Type() == ssh.KeyAlgoRSA {
					assert.Equal(t, sig.Signature.Format, ssh.KeyAlgoRSASHA512)
				} else {
					assert.Equal(t, sig.Signature.Format, pub.Type())
				}

				// Round trip as much as possible.
				armored := sshsig.Armor(sig)
				assert.NotNil(t, armored)
				sigFromArmored, err := sshsig.Unarmor(armored)
				assert.NoError(t, err)

				// Verify the signature.
				assert.NoError(t, sshsig.Verify(bytes.NewReader(testMessage), sigFromArmored, pub, algo, testNamespace))

				// Verify against other message (should fail).
				err = sshsig.Verify(bytes.NewReader([]byte("faulty")), sig, pub, algo, testNamespace)
				assert.Error(t, err)
				assert.NotErrorIs(t, err, sshsig.ErrPublicKeyMismatch)

				// Verify against other hash algorithm (should fail).
				assert.Error(t, sshsig.Verify(bytes.NewReader(testMessage), sig, pub, oppositeAlgorithm(algo), testNamespace))

				// Generate a second key to verify (and fail) with.
				cOtherPub, _, err := key.generate()
				assert.NoError(t, err)
				otherPub, err := ssh.NewPublicKey(cOtherPub)
				assert.NoError(t, err)

				// Ensure the fingerprints are different.
				assert.False(t, ssh.FingerprintSHA256(pub) == ssh.FingerprintSHA256(otherPub))

				// Verify against other key (should fail).
				assert.ErrorIs(t, sshsig.Verify(bytes.NewReader(testMessage), sig, otherPub, algo, testNamespace), sshsig.ErrPublicKeyMismatch)

				// Verify against other namespace (should fail).
				oterNamespace := "faulty"
				assert.Error(t, sshsig.Verify(bytes.NewReader(testMessage), sig, otherPub, algo, oterNamespace))
			})
		}
	}
}
