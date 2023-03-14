package sshsig_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"testing/iotest"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"

	"github.com/hiddeco/sshsig"
)

func TestVerify(t *testing.T) {
	t.Run("different namespace", func(t *testing.T) {
		cPub, _, err := ed25519.GenerateKey(rand.Reader)
		assert.NoError(t, err)

		pub, err := ssh.NewPublicKey(cPub)
		assert.NoError(t, err)

		namespaceA := "foo"
		namespaceB := "bar"

		err = sshsig.Verify(nil, &sshsig.Signature{
			PublicKey: pub, Namespace: namespaceA,
		}, pub, sshsig.HashSHA256, namespaceB)
		assert.ErrorIs(t, err, sshsig.ErrNamespaceMismatch)
	})

	t.Run("unsupported hash algorithm", func(t *testing.T) {
		cPub, _, err := ed25519.GenerateKey(rand.Reader)
		assert.NoError(t, err)

		pub, err := ssh.NewPublicKey(cPub)
		assert.NoError(t, err)

		err = sshsig.Verify(nil, &sshsig.Signature{
			PublicKey: pub,
		}, pub, "unsupported", "")
		assert.ErrorIs(t, err, sshsig.ErrUnsupportedHashAlgorithm)
	})

	t.Run("message read error", func(t *testing.T) {
		cPub, _, err := ed25519.GenerateKey(rand.Reader)
		assert.NoError(t, err)

		pub, err := ssh.NewPublicKey(cPub)
		assert.NoError(t, err)

		mockErr := errors.New("read error")
		err = sshsig.Verify(iotest.ErrReader(mockErr), &sshsig.Signature{
			PublicKey: pub,
		}, pub, sshsig.HashSHA256, "")
		assert.ErrorIs(t, err, mockErr)
	})
}
