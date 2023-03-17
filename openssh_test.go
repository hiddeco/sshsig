package sshsig_test

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh"

	"github.com/hiddeco/sshsig"
)

const (
	// ed25519PrivateKey is an ED25519 private key, generated with:
	// `ssh-keygen -t ed25519 -C "sshsig@example.com"`
	ed25519PrivateKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDTcDBzPJS3L3vhzHSpo2mp0Z5HThNEpt2VMZI7+S04IAAAAJjcTWiZ3E1o
mQAAAAtzc2gtZWQyNTUxOQAAACDTcDBzPJS3L3vhzHSpo2mp0Z5HThNEpt2VMZI7+S04IA
AAAEAAQVJdHf/P7QGmNhr/QhAA82Gees/wN41nUfr515ujCNNwMHM8lLcve+HMdKmjaanR
nkdOE0Sm3ZUxkjv5LTggAAAAEnNzaHNpZ0BleGFtcGxlLmNvbQECAw==
-----END OPENSSH PRIVATE KEY-----`
	// ed25519PublicKey is the public key corresponding to ed25519PrivateKey.
	ed25519PublicKey = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINNwMHM8lLcve+HMdKmjaanRnkdOE0Sm3ZUxkjv5LTgg sshsig@example.com`

	// ecdsaPrivateKey is a ECDSA-P256 private key, generated with:
	// `ssh-keygen -t ecdsa -b 256 -C "sshsig@example.com"`
	ecdsaPrivateKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAaAAAABNlY2RzYS
1zaGEyLW5pc3RwMjU2AAAACG5pc3RwMjU2AAAAQQQ4hi5YXS//DxdWs4tRrfScyEvCJd2x
/hqjDzyR+md8D9mf5eGv2dGH3t601XX8qq/VUT86f9gf7T3giGVq3IQtAAAAsPbhCNX24Q
jVAAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDiGLlhdL/8PF1az
i1Gt9JzIS8Il3bH+GqMPPJH6Z3wP2Z/l4a/Z0Yfe3rTVdfyqr9VRPzp/2B/tPeCIZWrchC
0AAAAgat7A5GYa+yEHE/QWotjwVO3cPxGuyn6ErMUKhIzzetwAAAASc3Noc2lnQGV4YW1w
bGUuY29tAQIDBAUG
-----END OPENSSH PRIVATE KEY-----`
	// ecdsaPublicKey is the public key corresponding to ecdsaPrivateKey.
	ecdsaPublicKey = `ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDiGLlhdL/8PF1azi1Gt9JzIS8Il3bH+GqMPPJH6Z3wP2Z/l4a/Z0Yfe3rTVdfyqr9VRPzp/2B/tPeCIZWrchC0= sshsig@example.com`

	// rsaPrivateKey is a 1024-bit RSA key, generated with
	// `ssh-keygen -t rsa -b 1024 -C "sshsig@example.com"`
	rsaPrivateKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAIEAtqER/SEhWnXVYnijqazzf8LkA4bjSrCNUUSg8nn0H9R/f7jb0au7
6ba/ap4RmmzxKzzpkI1eUrEcPG6/g8N/VYFEU6pszHP2lhjFcbF3Y2zNFm9ygaaTtx61EY
7Rtr7W9SkqtE4yeo0Wnnlc1sV9JVcKTndIRSuQogMKyXeF9tEAAAIItMvAebTLwHkAAAAH
c3NoLXJzYQAAAIEAtqER/SEhWnXVYnijqazzf8LkA4bjSrCNUUSg8nn0H9R/f7jb0au76b
a/ap4RmmzxKzzpkI1eUrEcPG6/g8N/VYFEU6pszHP2lhjFcbF3Y2zNFm9ygaaTtx61EY7R
tr7W9SkqtE4yeo0Wnnlc1sV9JVcKTndIRSuQogMKyXeF9tEAAAADAQABAAAAgQCu9ozHVz
Ae+/icSDtzWNBHPC05+8ZRTed1TixrYM6yl+A2OqHNs5tpgrzLpffzXB+IbujMpcMRsb/9
XZR45Zhcb8Zg6yUOeb9zAoTGYLmIBcKEVRe23AkBY0UDordM758oHmX37Etxr8ij/mg7Uq
TPthJkdd8XxO47gT91OrYfyQAAAEAdPeOlb222qWeY1mC8hKTESPAho+DZxBKCy93fNhUD
4M55ef2CQsxYreDnfFDNJOxgfFXUU403wYLPMJJ0lMDfAAAAQQDwVpAPLN3fVYNidS8H0x
AUfNkjLYfE5k4O2TmeYXSbcrCVzUjvb/4ZcCJWSechfJGNX5qyGTrE0ho54Q4HVu03AAAA
QQDCh8deIWcBdCmDRjO3mE1xoav3fCi3BVH7qodIRuYy1hV3xOSUjwnO5mC1YmeTfyL0uR
4XBqbl1cLmti+/bwA3AAAAEnNzaHNpZ0BleGFtcGxlLmNvbQ==
-----END OPENSSH PRIVATE KEY-----`
	// rsaPublicKey is the public key corresponding to rsaPrivateKey.
	rsaPublicKey = `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC2oRH9ISFaddVieKOprPN/wuQDhuNKsI1RRKDyefQf1H9/uNvRq7vptr9qnhGabPErPOmQjV5SsRw8br+Dw39VgURTqmzMc/aWGMVxsXdjbM0Wb3KBppO3HrURjtG2vtb1KSq0TjJ6jRaeeVzWxX0lVwpOd0hFK5CiAwrJd4X20Q== sshsig@example.com`

	// otherPrivateKey is a ED25519 key to test failure cases with, generated with:
	// ssh-keygen -t ed25519 -C "sshsig-other@example.com"
	otherPrivateKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDTcDBzPJS3L3vhzHSpo2mp0Z5HThNEpt2VMZI7+S04IAAAAJjcTWiZ3E1o
mQAAAAtzc2gtZWQyNTUxOQAAACDTcDBzPJS3L3vhzHSpo2mp0Z5HThNEpt2VMZI7+S04IA
AAAEAAQVJdHf/P7QGmNhr/QhAA82Gees/wN41nUfr515ujCNNwMHM8lLcve+HMdKmjaanR
nkdOE0Sm3ZUxkjv5LTggAAAAEnNzaHNpZ0BleGFtcGxlLmNvbQECAw==
-----END OPENSSH PRIVATE KEY-----`
	// otherPublicKey is the public key corresponding to otherPrivateKey.
	otherPublicKey = `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOrvP89uyupCbqyFcCz1nNtKuLT8YIUkj0Vhf/xYamSs sshsig-other@example.com`
)

func TestSignToOpenSSH(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("skipping: missing ssh-keygen in PATH")
	}

	var (
		testNamespace = "file"
		testMessage   = []byte("I like your game but we have to change the rules.")
	)

	tests := []struct {
		name       string
		publicKey  string
		privateKey string
	}{
		{"ed25519", ed25519PublicKey, ed25519PrivateKey},
		{"ecdsa", ecdsaPublicKey, ecdsaPrivateKey},
		{"rsa", rsaPublicKey, rsaPrivateKey},
	}
	for _, tt := range tests {
		tt := tt
		for _, a := range sshsig.SupportedHashAlgorithms() {
			algo := a
			t.Run(fmt.Sprintf("%s-%s", tt.name, algo), func(t *testing.T) {
				// Make test go brrrr...
				t.Parallel()

				// Temporary directory used as working directory for ssh-keygen.
				tmp := t.TempDir()

				// Load the private key.
				signer, err := ssh.ParsePrivateKey([]byte(tt.privateKey))
				assert.NoError(t, err)

				// Sign a message.
				sig, err := sshsig.Sign(bytes.NewReader(testMessage), signer, algo, testNamespace)
				assert.NoError(t, err)

				// Write the PEM to a file.
				sigFile := filepath.Join(tmp, "sig")
				assert.NoError(t, os.WriteFile(sigFile, sshsig.Armor(sig), 0o600))

				// Construct allowed_signers file.
				id, row := allowedSigner(t, tt.publicKey)
				idOther, rowOther := allowedSigner(t, otherPublicKey)

				allowedSigners := fmt.Sprintf("%s\n%s", row, rowOther)
				allowedSignersFile := filepath.Join(tmp, "allowed_signers")
				assert.NoError(t, os.WriteFile(allowedSignersFile, []byte(allowedSigners), 0o600))

				// Check the signature.
				_, err = execOpenSSH(t, tmp, bytes.NewReader(testMessage), "-Y", "check-novalidate", "-f", allowedSignersFile,
					"-n", testNamespace, "-s", sigFile)
				assert.NoError(t, err)

				// Verify the signature.
				_, err = execOpenSSH(t, tmp, bytes.NewReader(testMessage), "-Y", "verify", "-f", allowedSignersFile,
					"-I", id, "-n", testNamespace, "-s", "sig")
				assert.NoError(t, err)

				// Different key.
				out, err := execOpenSSH(t, tmp, bytes.NewReader(testMessage), "-Y", "verify", "-f", allowedSignersFile,
					"-I", idOther, "-n", testNamespace, "-s", sigFile)
				assert.Error(t, err, out)

				// Different namespace.
				out, err = execOpenSSH(t, tmp, bytes.NewReader(testMessage), "-Y", "verify", "-f", allowedSignersFile,
					"-I", id, "-n", "other", "-s", sigFile)
				assert.Error(t, err, out)

				// Different data.
				out, err = execOpenSSH(t, tmp, bytes.NewReader([]byte("other")), "-Y", "verify", "-f", allowedSignersFile,
					"-I", id, "-n", testNamespace, "-s", sigFile)
				assert.Error(t, err, out)
			})
		}
	}
}

func TestVerifyFromOpenSSH(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("skipping: missing ssh-keygen in PATH")
	}

	var (
		testNamespace = "file"
		testMessage   = []byte("I never failed to convince an audience that the best thing they could do was to go away.")
		sshVersion    = getSSHVersion(t)
		// Only ssh-keygen 8.9 and later allow selection of hash at sshsig
		// signing time. This is unfortunately not available in the version of
		// OpenSSH that ships with macOS in GitHub Actions.
		// xref: https://www.openssh.com/txt/release-8.9
		supportsHashSelection = sshVersion >= 8.9
	)

	tests := []struct {
		name       string
		publicKey  string
		privateKey string
	}{
		{"ed25519", ed25519PublicKey, ed25519PrivateKey},
		{"ecdsa", ecdsaPublicKey, ecdsaPrivateKey},
		{"rsa", rsaPublicKey, rsaPrivateKey},
	}
	for _, tt := range tests {
		tt := tt
		for _, a := range sshsig.SupportedHashAlgorithms() {
			algo := a
			t.Run(fmt.Sprintf("%s-%s", tt.name, algo), func(t *testing.T) {
				if !supportsHashSelection && algo == sshsig.HashSHA256 {
					t.Skipf("skipping: ssh-keygen %v does not allow selection of hash at sshsig signing time", sshVersion)
				}

				// Make test go brrrr...
				t.Parallel()

				// Temporary directory used as working directory for ssh-keygen.
				tmp := t.TempDir()

				// Write the private key to a file, has to end with newline or
				// ssh-keygen will complain with "couldn't load".
				keyFile := filepath.Join(tmp, "id")
				assert.NoError(t, os.WriteFile(keyFile, []byte(tt.privateKey+"\n"), 0o600))
				// Write the public key to a file as well. This is required
				// because OpenSSH <8.3 does not support reading the public key
				// from the private key file.
				pubFile := filepath.Join(tmp, "id.pub")
				assert.NoError(t, os.WriteFile(pubFile, []byte(tt.publicKey+"\n"), 0o600))

				// Write the message to a file.
				msgFile := filepath.Join(tmp, "message")
				assert.NoError(t, os.WriteFile(msgFile, testMessage, 0o600))

				// Sign the message.
				args := []string{"-Y", "sign", "-n", testNamespace, "-f", keyFile}
				if supportsHashSelection {
					args = append(args, "-O", "hashalg="+algo.String())
				}
				_, err := execOpenSSH(t, tmp, nil, append(args, msgFile)...)
				assert.NoError(t, err)

				// Read and unmarshal signature.
				sigB, err := os.ReadFile(msgFile + ".sig")
				assert.NoError(t, err)
				sig, err := sshsig.Unarmor(sigB)
				assert.NoError(t, err)

				// Load the public key.
				pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(tt.publicKey))
				assert.NoError(t, err)

				// Verify the signature.
				err = sshsig.Verify(bytes.NewReader(testMessage), sig, pub, sig.HashAlgorithm, testNamespace)
				assert.NoError(t, err)

				// Different key.
				otherPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(otherPublicKey))
				assert.NoError(t, err)
				err = sshsig.Verify(bytes.NewReader(testMessage), sig, otherPub, sig.HashAlgorithm, testNamespace)
				assert.ErrorIs(t, err, sshsig.ErrPublicKeyMismatch)

				// Different algorithm.
				err = sshsig.Verify(bytes.NewReader(testMessage), sig, pub, oppositeAlgorithm(algo), testNamespace)
				assert.Error(t, err)

				// Different namespace.
				err = sshsig.Verify(bytes.NewReader(testMessage), sig, pub, sig.HashAlgorithm, "other")
				assert.ErrorIs(t, err, sshsig.ErrNamespaceMismatch)

				// Different data.
				err = sshsig.Verify(bytes.NewReader([]byte("other")), sig, pub, sig.HashAlgorithm, testNamespace)
				assert.Error(t, err)
			})
		}
	}
}

// allowedSigner returns the identifier (comment) of the key, and the row for
// the allowed_signers file.
func allowedSigner(t *testing.T, publicKey string) (id, row string) {
	t.Helper()

	fields := strings.Fields(publicKey)
	if len(fields) != 3 {
		t.Fatalf("public key is missing element: %s", publicKey)
	}

	id = fields[2]
	row = fmt.Sprintf("%s %s %s", id, fields[0], fields[1])
	return
}

// execOpenSSH executes ssh-keygen with the given arguments in the given dir,
// and returns the combined output. When stdin is not nil, it is passed to
// ssh-keygen. If ssh-keygen returns an error, the error is wrapped with the
// combined output.
func execOpenSSH(t *testing.T, dir string, stdin io.Reader, args ...string) ([]byte, error) {
	t.Helper()
	t.Logf("ssh-keygen %s", args)

	cmd := exec.Command("ssh-keygen", args...)
	cmd.Dir = dir
	cmd.Stdin = stdin
	b, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, string(b))
	}
	return b, nil
}

func getSSHVersion(t *testing.T) float64 {
	t.Helper()

	out, err := exec.Command("ssh", "-V").CombinedOutput()
	if err != nil {
		t.Fatalf("failed to get SSH version: %s", out)
	}

	re := regexp.MustCompile(`OpenSSH.*?_(\d+\.\d+)(p\d+)?`)
	matches := re.FindStringSubmatch(string(out))
	if len(matches) < 2 {
		t.Fatalf("failed to parse SSH version: %s", out)
	}
	v, err := strconv.ParseFloat(matches[1], 64)
	if err != nil {
		t.Fatalf("failed to extract SSH version: %s", out)
	}
	return v
}

// oppositeAlgorithm returns the opposite hash algorithm.
func oppositeAlgorithm(algo sshsig.HashAlgorithm) sshsig.HashAlgorithm {
	switch algo {
	case sshsig.HashSHA256:
		return sshsig.HashSHA512
	case sshsig.HashSHA512:
		return sshsig.HashSHA256
	default:
		panic("unknown hash algorithm")
	}
}
