package client

import (
	"Heimdall/internal/agent/native"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"time"
)

func parseCA(data []byte) (*x509.Certificate, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("invalid CA certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !cert.IsCA || !cert.BasicConstraintsValid {
		return nil, errors.New("invalid CA authority")
	}
	if err = cert.CheckSignatureFrom(cert); err != nil {
		return nil, err
	}
	return cert, nil
}

func renewedCA(c Config, data []byte) (*x509.Certificate, error) {
	configured, err := os.ReadFile(c.CAFile)
	if err != nil {
		return nil, err
	}
	old, err := parseCA(configured)
	if err != nil {
		return nil, err
	}
	next, err := parseCA(data)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(old.RawSubjectPublicKeyInfo, next.RawSubjectPublicKeyInfo) || !bytes.Equal(old.RawSubject, next.RawSubject) || time.Now().Before(next.NotBefore) || !time.Now().Before(next.NotAfter) {
		return nil, errors.New("renewed CA does not match the configured trust key")
	}
	return next, nil
}

func trustedPool(c Config) (*x509.CertPool, error) {
	data, err := os.ReadFile(filepath.Join(c.Directory, "trusted-ca.pem"))
	if errors.Is(err, os.ErrNotExist) {
		return pool(c.CAFile)
	}
	if err != nil {
		return nil, err
	}
	cert, err := renewedCA(c, data)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return roots, nil
}

// TLS authenticates the response. Only a re-signed certificate of the same
// configured CA key may refresh trust; changing the CA key requires an
// independent administrator-controlled distribution step.
func acceptCertificate(c Config, id identity, leaf, ca []byte) error {
	root, err := renewedCA(c, ca)
	if err != nil {
		return err
	}
	pair, err := tls.X509KeyPair(leaf, id.Key)
	if err != nil {
		return err
	}
	cert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return err
	}
	if cert.Subject.CommonName != id.NodeID {
		return errors.New("renewed certificate belongs to another node")
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	if _, err = cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		return err
	}
	return native.AtomicWrite(filepath.Join(c.Directory, "trusted-ca.pem"), ca, 0600)
}
