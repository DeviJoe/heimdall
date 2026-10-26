package helper

import (
	"Heimdall/internal/agent/native"
	"Heimdall/internal/platform/security"
	"Heimdall/internal/synchronization"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
)

// Bootstrap pins the root operator's enrollment intent before the unprivileged
// network process receives its first signed manifest. The journal never repins
// itself when an environment variable changes.
type Bootstrap struct {
	Nonce     string `json:"nonce"`
	TokenHash string `json:"token_hash"`
}

func validPin(value string) bool {
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 32
}
func loadBootstrap(dir, token string, initialized bool) (Bootstrap, error) {
	var pin Bootstrap
	path := filepath.Join(dir, "bootstrap.json")
	info, err := os.Lstat(path)
	if err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return pin, errors.New("unsafe enrollment binding journal")
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return pin, err
		}
		if err = json.Unmarshal(raw, &pin); err != nil || !validPin(pin.Nonce) || !validPin(pin.TokenHash) {
			return pin, errors.New("invalid enrollment binding journal")
		}
		return pin, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return pin, err
	}
	// Previously enrolled nodes already pin their node ID in the root checkpoint.
	if initialized {
		return pin, nil
	}
	if token == "" {
		return pin, errors.New("root helper initial enrollment requires a join token")
	}
	pin = Bootstrap{Nonce: security.HashToken(security.Random(32)), TokenHash: security.HashToken(token)}
	raw, _ := json.Marshal(pin)
	return pin, native.AtomicWrite(path, raw, 0600)
}
func (b Bootstrap) verify(state synchronization.Snapshot, initialized bool) error {
	if initialized {
		return nil
	}
	if !validPin(b.Nonce) || !validPin(b.TokenHash) || subtle.ConstantTimeCompare([]byte(b.Nonce), []byte(state.BootstrapNonce)) != 1 || subtle.ConstantTimeCompare([]byte(b.TokenHash), []byte(state.BootstrapTokenHash)) != 1 {
		return errors.New("signed manifest does not match this node's root enrollment binding")
	}
	return nil
}
