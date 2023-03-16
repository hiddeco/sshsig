package sshsig_test

import (
	"bytes"
	"fmt"

	"golang.org/x/crypto/ssh"

	"github.com/hiddeco/sshsig"
)

func ExampleSign() {
	// Load the private key to sign with.
	signer, err := ssh.ParsePrivateKey([]byte(ecdsaPrivateKey))
	if err != nil {
		panic(err)
	}

	// Sign a message with the private key, using an SHA-512 hash and the
	// namespace "file".
	message := []byte("Hello world!")
	sig, err := sshsig.Sign(bytes.NewReader(message), signer, sshsig.HashSHA512, "file")
	if err != nil {
		panic(err)
	}

	// Print the signature in armored (PEM) format.
	armored := sshsig.Armor(sig)
	fmt.Printf("%s", armored)
}

func ExampleVerify() {
	// Load a public key to verify with.
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(ed25519PublicKey))
	if err != nil {
		panic(err)
	}

	// Load the armored (PEM) signature to verify.
	armored := []byte(`-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAAGgAAAATZWNkc2Etc2hhMi1uaXN0cDI1NgAAAAhuaXN0cDI1
NgAAAEEEOIYuWF0v/w8XVrOLUa30nMhLwiXdsf4aow88kfpnfA/Zn+Xhr9nRh97e
tNV1/Kqv1VE/On/YH+094IhlatyELQAAAARmaWxlAAAAAAAAAAZzaGE1MTIAAABk
AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAABJAAAAIBXp90537Om8Xbv0iTxVwvSy
iZmhAca7kPt0uSg0IVtTAAAAIQCbN+co4miAJ7t9XLIQuOaOQCM5P0AxRCdsMG4e
BnAL0w==
-----END SSH SIGNATURE-----`)
	sig, err := sshsig.Unarmor(armored)
	if err != nil {
		panic(err)
	}

	// Verify the signature, using the same hash algorithm and namespace as
	// used to sign the message. If the signature is valid, no error is
	// returned.
	message := []byte("Hello world!")
	if err := sshsig.Verify(bytes.NewReader(message), sig, pub, sig.HashAlgorithm, sig.Namespace); err != nil {
		panic(err)
	}

	// When more strict verification is required, the hash algorithm and/or
	// namespace can be checked against the expected values.
	if err := sshsig.Verify(bytes.NewReader(message), sig, pub, sshsig.HashSHA512, "file"); err != nil {
		panic(err)
	}
}
