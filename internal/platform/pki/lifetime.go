package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"time"
)

func replacePublicCertificate(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".certificate-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err = f.Chmod(0644); err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// Run by the privileged PKI initialization job before control-plane startup.
// Renew certificates with existing keys; agent trust and manifest pins stay
// valid. Never generate a replacement private key during an upgrade.
func renewLifetimes(dir string) error {
	a, err := Load(dir)
	if err != nil {
		return err
	}
	now := time.Now()
	if a.Certificate.NotAfter.Before(now.AddDate(11, 0, 0)) {
		template := *a.Certificate
		template.SerialNumber = serial()
		template.NotBefore = now.Add(-time.Minute)
		template.NotAfter = now.AddDate(20, 0, 0)
		der, err := x509.CreateCertificate(rand.Reader, &template, &template, a.Key.Public(), a.Key)
		if err != nil {
			return err
		}
		if err = replacePublicCertificate(filepath.Join(dir, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})); err != nil {
			return err
		}
		a.Certificate, err = x509.ParseCertificate(der)
		if err != nil {
			return err
		}
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, "server.pem"), filepath.Join(dir, "server.key"))
	if err != nil {
		return err
	}
	server, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return err
	}
	if server.NotAfter.Before(now.AddDate(9, 0, 0)) {
		template := *server
		template.SerialNumber = serial()
		template.NotBefore = now.Add(-time.Minute)
		template.NotAfter = now.AddDate(10, 0, 0)
		key := pair.PrivateKey.(crypto.Signer)
		der, err := x509.CreateCertificate(rand.Reader, &template, a.Certificate, key.Public(), a.Key)
		if err != nil {
			return err
		}
		return replacePublicCertificate(filepath.Join(dir, "server.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	}
	return nil
}
