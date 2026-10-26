package httpapi

import (
	"Heimdall/internal/application"
	"Heimdall/internal/platform/security"
	"encoding/json"
	"net/http"
	"net/url"
	"time"
)

type totpRotation struct {
	Secret  string `json:"secret"`
	Version int64  `json:"version"`
}

func (s *Server) totpRotateBegin(w http.ResponseWriter, r *http.Request) {
	p := Principal(r.Context())
	if p.TokenID != "" || p.Restricted {
		Fail(w, application.ErrForbidden)
		return
	}
	u, err := s.Store.User(r.Context(), p.UserID)
	if err != nil {
		Fail(w, err)
		return
	}
	if !u.TOTPEnabled {
		JSON(w, 400, map[string]string{"error": "TOTP ещё не настроен"})
		return
	}
	secret := security.NewTOTPSecret()
	raw, _ := json.Marshal(totpRotation{s.Cipher.Seal(secret), u.AuthVersion})
	if err = s.Redis.Set(r.Context(), "totp-rotate:"+p.UserID, raw, 5*time.Minute).Err(); err != nil {
		Fail(w, err)
		return
	}
	JSON(w, 200, map[string]string{"secret": secret, "uri": "otpauth://totp/Heimdall:" + url.PathEscape(p.Login) + "?issuer=Heimdall&algorithm=SHA1&digits=6&period=30&secret=" + secret})
}

func (s *Server) totpRotateFinish(w http.ResponseWriter, r *http.Request) {
	p := Principal(r.Context())
	if p.TokenID != "" || p.Restricted {
		Fail(w, application.ErrForbidden)
		return
	}
	var v struct {
		Code string `json:"code"`
	}
	if !Decode(w, r, &v) {
		return
	}
	if !s.limited(r, "totp-rotate") {
		JSON(w, 429, map[string]string{"error": "Подождите минуту перед новой попыткой"})
		return
	}
	raw, err := s.Redis.Get(r.Context(), "totp-rotate:"+p.UserID).Bytes()
	var pending totpRotation
	if err != nil || json.Unmarshal(raw, &pending) != nil {
		JSON(w, 400, map[string]string{"error": "Начните замену TOTP заново"})
		return
	}
	secret, err := s.Cipher.Open(pending.Secret)
	if _, ok := security.VerifyTOTP(secret, v.Code, time.Now()); err != nil || !ok {
		JSON(w, 400, map[string]string{"error": "Неверный код нового TOTP"})
		return
	}
	codes, hashes := recoveryCodes()
	if err = s.Store.RotateTOTP(r.Context(), p.UserID, pending.Version, pending.Secret, hashes); err != nil {
		Fail(w, err)
		return
	}
	s.Redis.Del(r.Context(), "totp-rotate:"+p.UserID)
	if err = s.newSession(w, r, p.UserID); err != nil {
		Fail(w, err)
		return
	}
	JSON(w, 200, map[string]any{"ok": true, "recovery_codes": codes})
}
