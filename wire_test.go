package sshsig

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_signedData_Marshal(t *testing.T) {
	t.Run("has magic preamble", func(t *testing.T) {
		s := signedData{}
		m := s.Marshal()
		assert.Equal(t, magicPreamble[:], m[:6])
	})
}

func Test_blob_Valid(t *testing.T) {
	t.Run("unsupported version", func(t *testing.T) {
		b := blob{
			Version: 0,
		}
		assert.ErrorIs(t, b.Validate(), ErrUnsupportedSignatureVersion)
	})

	t.Run("invalid magic preamble", func(t *testing.T) {
		b := blob{
			Version:       sigVersion,
			MagicPreamble: [6]byte{'a', 'b', 'c', 'd', 'e', 'f'},
		}
		assert.ErrorIs(t, b.Validate(), ErrInvalidMagicPreamble)
	})

	t.Run("unsupported hash algorithm", func(t *testing.T) {
		b := blob{
			Version:       sigVersion,
			MagicPreamble: magicPreamble,
			HashAlgorithm: "foo",
		}
		assert.ErrorIs(t, b.Validate(), ErrUnsupportedHashAlgorithm)
	})

	t.Run("valid", func(t *testing.T) {
		b := blob{
			Version:       sigVersion,
			MagicPreamble: magicPreamble,
			HashAlgorithm: "sha256",
		}
		assert.NoError(t, b.Validate())
	})
}

func Test_blob_Marshal(t *testing.T) {
	t.Run("has magic preamble", func(t *testing.T) {
		b := blob{
			Version:       1,
			MagicPreamble: magicPreamble,
		}
		m := b.Marshal()
		assert.Equal(t, magicPreamble[:], m[:6])
	})
}
