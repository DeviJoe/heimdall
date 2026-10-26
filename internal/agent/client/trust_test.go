package client

import (
	"Heimdall/internal/platform/pki"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCertificateReplacementChecksIdentityAndPinnedCAAndPersistsTrust(t *testing.T) {
	dir := t.TempDir()
	if err := pki.Init(dir); err != nil {
		t.Fatal(err)
	}
	a, err := pki.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := csr(key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	id := identity{NodeID: "node", Key: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})}
	c := Config{CAFile: filepath.Join(dir, "ca.pem"), Directory: t.TempDir()}
	leaf, _, err := a.Issue(id.NodeID, csr, 3650*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = acceptCertificate(c, id, leaf, a.PublicCertificate()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(c.Directory, "trusted-ca.pem"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("trust file is not private")
	}
	if _, err = trustedPool(c); err != nil {
		t.Fatal(err)
	}
	other, _, err := a.Issue("other-node", csr, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = acceptCertificate(c, id, other, a.PublicCertificate()); err == nil {
		t.Fatal("another node certificate accepted")
	}
	foreign := t.TempDir()
	if err = pki.Init(foreign); err != nil {
		t.Fatal(err)
	}
	foreignCA, err := pki.Load(foreign)
	if err != nil {
		t.Fatal(err)
	}
	if err = acceptCertificate(c, id, leaf, foreignCA.PublicCertificate()); err == nil {
		t.Fatal("CA key changed through a network response")
	}
	if _, err = trustedPool(c); err != nil {
		t.Fatal("rejected replacement damaged the active trust")
	}
}
