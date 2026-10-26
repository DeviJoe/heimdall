package pki

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestInitializationExtendsLegacyCertificatesWithoutChangingTrustKeys(t *testing.T) {
	dir := t.TempDir()
	if err := Init(dir); err != nil {
		t.Fatal(err)
	}
	a, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	old := *a.Certificate
	old.NotAfter = time.Now().AddDate(5, 0, 0)
	der, err := x509.CreateCertificate(rand.Reader, &old, &old, a.Key.Public(), a.Key)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		t.Fatal(err)
	}
	if err = Init(dir); err != nil {
		t.Fatal(err)
	}
	upgraded, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(upgraded.Certificate.RawSubjectPublicKeyInfo, a.Certificate.RawSubjectPublicKeyInfo) || !bytes.Equal(upgraded.SigningKey, a.SigningKey) {
		t.Fatal("upgrade changed a trust pin")
	}
	if upgraded.Certificate.NotAfter.Before(time.Now().AddDate(19, 0, 0)) {
		t.Fatal("CA cannot cover ten-year node certificates")
	}
	first := upgraded.Certificate.Raw
	if err = Init(dir); err != nil {
		t.Fatal(err)
	}
	upgraded, err = Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, upgraded.Certificate.Raw) {
		t.Fatal("every restart unnecessarily reissues the CA")
	}
}
