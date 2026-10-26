package pki

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"
	"time"
)

func TestCertificateIdentityAndStateSignature(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir); err != nil {
		t.Fatal(err)
	}
	a, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "forged-node"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	_, cert, err := a.Issue("server-assigned-id", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), time.Hour)
	if err != nil || cert.Subject.CommonName != "server-assigned-id" {
		t.Fatal("CSR controlled node identity")
	}
	pool := x509.NewCertPool()
	pool.AddCert(a.Certificate)
	if _, err = cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatal(err)
	}
	payload := []byte("revision")
	signature, digest := a.Sign(payload)
	if len(digest) != 64 || !ed25519.Verify(a.SigningKey.Public().(ed25519.PublicKey), payload, signature) {
		t.Fatal("signature invalid")
	}
	if ed25519.Verify(a.SigningKey.Public().(ed25519.PublicKey), []byte("changed"), signature) {
		t.Fatal("modified state accepted")
	}
}
