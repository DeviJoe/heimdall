package credentials

import (
	"crypto/rsa"
	"errors"
	"golang.org/x/crypto/ssh"
	"strings"
	"time"
)

type Key struct {
	ID          string    `json:"id"`
	UserID      string    `json:"user_id"`
	Name        string    `json:"name"`
	PublicKey   string    `json:"public_key"`
	Fingerprint string    `json:"fingerprint"`
	Algorithm   string    `json:"algorithm"`
	Status      string    `json:"status"`
	ExpiresAt   time.Time `json:"expires_at"`
	CreatedAt   time.Time `json:"created_at"`
}

func Parse(public string, requireSK bool) (string, string, string, error) {
	if len(public) > 16384 {
		return "", "", "", errors.New("public key too large")
	}
	key, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(public))
	if err != nil || len(options) > 0 || strings.TrimSpace(string(rest)) != "" {
		return "", "", "", errors.New("expected one public key without authorized_keys options")
	}
	algorithm := key.Type()
	if requireSK && algorithm != "sk-ssh-ed25519@openssh.com" && algorithm != "sk-ecdsa-sha2-nistp256@openssh.com" {
		return "", "", "", errors.New("security-key-backed SSH key required")
	}
	switch algorithm {
	case "ssh-ed25519", "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com":
	case "ssh-rsa":
		cryptoKey, ok := key.(ssh.CryptoPublicKey)
		if !ok {
			return "", "", "", errors.New("invalid RSA key")
		}
		rsaKey, ok := cryptoKey.CryptoPublicKey().(*rsa.PublicKey)
		if !ok || rsaKey.N.BitLen() < 3072 {
			return "", "", "", errors.New("RSA keys must have at least 3072 bits")
		}
	default:
		return "", "", "", errors.New("unsupported SSH algorithm")
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))), ssh.FingerprintSHA256(key), algorithm, nil
}
