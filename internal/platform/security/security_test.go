package security

import (
	"github.com/GehirnInc/crypt/sha512_crypt"
	"strings"
	"testing"
	"time"
)

func TestPasswordsAndLinuxHash(t *testing.T) {
	password := "correct horse battery staple"
	hash, err := PasswordHash(password)
	if err != nil || !VerifyPassword(hash, password) || VerifyPassword(hash, "wrong") {
		t.Fatal("web password verification failed")
	}
	linux, err := LinuxHash(password)
	if err != nil || !strings.HasPrefix(linux, "$6$rounds=100000$") {
		t.Fatalf("invalid Linux hash: %v", err)
	}
	if err = sha512_crypt.New().Verify(linux, []byte(password)); err != nil {
		t.Fatal(err)
	}
	if VerifyPassword("$argon2id$v=19$m=999999999,t=3,p=1$AA$AA", password) {
		t.Fatal("unsafe hash parameters accepted")
	}
}
func TestCipherIntegrity(t *testing.T) {
	cipher, err := NewCipher(Random(32))
	if err != nil {
		t.Fatal(err)
	}
	sealed := cipher.Seal("factor-secret")
	plain, err := cipher.Open(sealed)
	if err != nil || plain != "factor-secret" {
		t.Fatal("roundtrip failed")
	}
	raw := []byte(sealed)
	raw[len(raw)/2] ^= 1
	if _, err = cipher.Open(string(raw)); err == nil {
		t.Fatal("modified ciphertext accepted")
	}
}
func TestTOTPVectorAndWindow(t *testing.T) {
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	if got := TOTP(secret, 1); got != "287082" {
		t.Fatalf("RFC6238 truncated 6-digit vector: %s", got)
	}
	now := time.Unix(59, 0)
	step, ok := VerifyTOTP(secret, "287082", now)
	if !ok || step != 1 {
		t.Fatal("valid OTP rejected")
	}
	if _, ok = VerifyTOTP(secret, "287082", now.Add(2*time.Minute)); ok {
		t.Fatal("expired OTP accepted")
	}
	if _, ok = VerifyTOTP(secret, "2870820", now); ok {
		t.Fatal("wrong code length accepted")
	}
}
