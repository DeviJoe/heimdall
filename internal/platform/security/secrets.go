package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/GehirnInc/crypt/sha512_crypt"
	"golang.org/x/crypto/argon2"
	"strconv"
	"strings"
)

func Random(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func HashToken(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func PasswordHash(password string) (string, error) {
	if len(password) < 12 || len(password) > 1024 {
		return "", errors.New("password must contain 12 to 1024 bytes")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, 3, 64*1024, 1, 32)
	return fmt.Sprintf("$argon2id$v=19$m=65536,t=3,p=1$%s$%s", base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}
func VerifyPassword(hash, password string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != "v=19" {
		return false
	}
	var memory, iterations uint32
	var parallel uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallel); err != nil || memory > 128*1024 || memory < 19*1024 || iterations < 2 || iterations > 8 || parallel != 1 {
		return false
	}
	salt, e1 := base64.RawStdEncoding.DecodeString(parts[4])
	want, e2 := base64.RawStdEncoding.DecodeString(parts[5])
	if e1 != nil || e2 != nil || len(salt) != 16 || len(want) != 32 {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, iterations, memory, parallel, 32)
	return subtle.ConstantTimeCompare(got, want) == 1
}
func LinuxHash(password string) (string, error) {
	if len(password) < 12 || len(password) > 1024 {
		return "", errors.New("Linux password must contain 12 to 1024 bytes")
	}
	salt := strings.NewReplacer("-", ".", "_", "/").Replace(Random(12))
	return sha512_crypt.New().Generate([]byte(password), []byte("$6$rounds=100000$"+salt+"$"))
}

type Cipher struct{ aead cipher.AEAD }

func NewCipher(secret string) (*Cipher, error) {
	key, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil || len(key) != 32 {
		return nil, errors.New("encryption key must be 32 base64url bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	return &Cipher{aead}, err
}
func (c *Cipher) Seal(plain string) string {
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(c.aead.Seal(nonce, nonce, []byte(plain), nil))
}
func (c *Cipher) Open(value string) (string, error) {
	data, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(data) < c.aead.NonceSize() {
		return "", errors.New("invalid encrypted secret")
	}
	plain, err := c.aead.Open(nil, data[:c.aead.NonceSize()], data[c.aead.NonceSize():], nil)
	return string(plain), err
}
func Int(s string) int { v, _ := strconv.Atoi(s); return v }
