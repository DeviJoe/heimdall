package security

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

func NewTOTPSecret() string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(Random(20)))
}
func TOTP(secret string, step int64) string {
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(secret))
	if err != nil {
		return ""
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	m := hmac.New(sha1.New, key)
	m.Write(counter[:])
	sum := m.Sum(nil)
	offset := sum[len(sum)-1] & 15
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1000000)
}
func VerifyTOTP(secret, code string, now time.Time) (int64, bool) {
	if len(code) != 6 {
		return 0, false
	}
	step := now.Unix() / 30
	for _, delta := range []int64{0, -1, 1} {
		if subtle.ConstantTimeCompare([]byte(TOTP(secret, step+delta)), []byte(code)) == 1 {
			return step + delta, true
		}
	}
	return 0, false
}
