package sshsig_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/hiddeco/sshsig"
)

func TestUnarmor(t *testing.T) {
	t.Run("invalid PEM block", func(t *testing.T) {
		got, err := sshsig.Unarmor(nil)
		assert.ErrorContains(t, err, "invalid PEM block")
		assert.Nil(t, got)
	})

	t.Run("invalid PEM type", func(t *testing.T) {
		got, err := sshsig.Unarmor([]byte("-----BEGIN FOO-----\n-----END FOO-----\n"))
		assert.ErrorContains(t, err, `invalid PEM type "FOO"`)
		assert.Nil(t, got)
	})

	t.Run("invalid PEM data", func(t *testing.T) {
		got, err := sshsig.Unarmor([]byte("-----BEGIN " + sshsig.PEMType + "-----\n-----END " + sshsig.PEMType + "-----\n"))
		assert.ErrorContains(t, err, "ssh: parse error in message")
		assert.Nil(t, got)
	})
}
