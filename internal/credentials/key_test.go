package credentials

import (
	"crypto/ed25519"
	"crypto/rand"
	"golang.org/x/crypto/ssh"
	"strings"
	"testing"
)

func TestCanonicalFingerprintAndOptions(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	canonical, fp, alg, err := Parse(line+" user comment", false)
	if err != nil || canonical != line || fp != ssh.FingerprintSHA256(key) || alg != "ssh-ed25519" {
		t.Fatal("key canonicalization failed")
	}
	if _, _, _, err = Parse(line, true); err == nil {
		t.Fatal("hardware-key policy bypassed")
	}
	for _, raw := range []string{`command="/bin/bash" ` + line, line + "\n" + line} {
		if _, _, _, err = Parse(raw, false); err == nil {
			t.Fatal("authorized_keys injection accepted")
		}
	}
}
