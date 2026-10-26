package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

// Recover explicitly replaces the transport credential of an existing node.
func Recover(ctx context.Context, c Config) error {
	if c.RecoveryToken == "" {
		return errors.New("node recovery token required")
	}
	data, err := os.ReadFile(filepath.Join(c.Directory, "identity.json"))
	if err != nil {
		return err
	}
	var id identity
	if err = json.Unmarshal(data, &id); err != nil {
		return err
	}
	roots, err := trustedPool(c)
	if err != nil {
		return err
	}
	return recoverIdentity(ctx, c, id, roots)
}

func recoverIdentity(ctx context.Context, c Config, id identity, roots *x509.CertPool) error {
	block, _ := pem.Decode(id.Key)
	if block == nil {
		return errors.New("invalid node private key")
	}
	raw, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return err
	}
	key, ok := raw.(ed25519.PrivateKey)
	if !ok {
		return errors.New("invalid node key type")
	}
	request, err := csr(key)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]any{"node_id": id.NodeID, "token": c.RecoveryToken, "csr": request})
	req, err := http.NewRequestWithContext(ctx, "POST", c.API+"/api/v1/agent/recover", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: c.ServerName, MinVersion: tls.VersionTLS13}}}
	defer hc.CloseIdleConnections()
	bounded, cancel := context.WithTimeout(ctx, 20e9)
	defer cancel()
	req = req.WithContext(bounded)
	response, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != 201 {
		return errors.New("node recovery refused")
	}
	var next identity
	if err = json.NewDecoder(io.LimitReader(response.Body, 65536)).Decode(&next); err != nil {
		return err
	}
	if next.NodeID != id.NodeID {
		return errors.New("recovery changed node identity")
	}
	id.Certificate = next.Certificate
	id.RenewRequested = true
	return save(c, id)
}
