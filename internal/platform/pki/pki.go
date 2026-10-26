package pki

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

type Authority struct {
	Certificate *x509.Certificate
	Key         crypto.Signer
	SigningKey  ed25519.PrivateKey
	Directory   string
}

func serial() *big.Int {
	v, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(err)
	}
	return v
}
func write(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(data); err != nil {
		return err
	}
	return f.Sync()
}
func Init(dir string) error {
	if _, err := os.Stat(filepath.Join(dir, "ca.pem")); err == nil {
		return renewLifetimes(dir)
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "Heimdall node CA"}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(20, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, key)
	if err != nil {
		return err
	}
	keyDer, _ := x509.MarshalPKCS8PrivateKey(key)
	if err = write(filepath.Join(dir, "ca.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDer}), 0600); err != nil {
		return err
	}
	if err = write(filepath.Join(dir, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		return err
	}
	serverPub, serverKey, _ := ed25519.GenerateKey(rand.Reader)
	server := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "controlplane"}, DNSNames: []string{"controlplane", "localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, NotBefore: now.Add(-time.Minute), NotAfter: now.AddDate(10, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	certDer, err := x509.CreateCertificate(rand.Reader, server, ca, serverPub, key)
	if err != nil {
		return err
	}
	serverDer, _ := x509.MarshalPKCS8PrivateKey(serverKey)
	if err = write(filepath.Join(dir, "server.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDer}), 0644); err != nil {
		return err
	}
	if err = write(filepath.Join(dir, "server.key"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: serverDer}), 0600); err != nil {
		return err
	}
	signPub, signKey, _ := ed25519.GenerateKey(rand.Reader)
	if err = write(filepath.Join(dir, "state.key"), signKey, 0600); err != nil {
		return err
	}
	return write(filepath.Join(dir, "state.pub"), signPub, 0644)
}
func (a *Authority) PublicCertificate() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.Certificate.Raw})
}
func Load(dir string) (*Authority, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, "ca.pem"))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("invalid CA")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, "ca.key"))
	if err != nil {
		return nil, err
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, errors.New("invalid CA key")
	}
	key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("invalid signer")
	}
	public, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || !bytes.Equal(public, cert.RawSubjectPublicKeyInfo) || !cert.IsCA || time.Now().After(cert.NotAfter) {
		return nil, errors.New("CA key mismatch, invalid authority or expired CA")
	}
	stateKey, err := os.ReadFile(filepath.Join(dir, "state.key"))
	if err != nil || len(stateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid state signing key")
	}
	statePublic, err := os.ReadFile(filepath.Join(dir, "state.pub"))
	if err != nil || !bytes.Equal(statePublic, ed25519.PrivateKey(stateKey).Public().(ed25519.PublicKey)) {
		return nil, errors.New("state signing key mismatch")
	}
	return &Authority{cert, signer, ed25519.PrivateKey(stateKey), dir}, nil
}
func (a *Authority) Issue(nodeID string, csrPEM []byte, ttl time.Duration) ([]byte, *x509.Certificate, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		return nil, nil, errors.New("invalid CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, nil, err
	}
	if err = csr.CheckSignature(); err != nil {
		return nil, nil, err
	}
	if _, ok := csr.PublicKey.(ed25519.PublicKey); !ok {
		return nil, nil, errors.New("node key must be Ed25519")
	}
	now := time.Now()
	cert := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: nodeID}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(ttl), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if ttl <= 0 || !now.Before(a.Certificate.NotAfter) {
		return nil, nil, errors.New("authority expired or invalid TTL")
	}
	if cert.NotAfter.After(a.Certificate.NotAfter) {
		cert.NotAfter = a.Certificate.NotAfter
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, a.Certificate, csr.PublicKey, a.Key)
	if err != nil {
		return nil, nil, err
	}
	parsed, _ := x509.ParseCertificate(der)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), parsed, nil
}
func (a *Authority) Sign(payload []byte) ([]byte, string) {
	h := sha256.Sum256(payload)
	return ed25519.Sign(a.SigningKey, payload), hex.EncodeToString(h[:])
}
func (a *Authority) TLS(clientAuth bool) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(filepath.Join(a.Directory, "server.pem"), filepath.Join(a.Directory, "server.key"))
	if err != nil {
		return nil, err
	}
	c := &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}}
	if clientAuth {
		pool := x509.NewCertPool()
		pool.AddCert(a.Certificate)
		c.ClientCAs = pool
		c.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return c, nil
}
