package httpapi

import (
	"Heimdall/internal/application"
	"Heimdall/internal/identity"
	"Heimdall/internal/platform/security"
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"net/http"
	"net/url"
	"time"
)

type webUser struct {
	User        identity.User
	Credentials []webauthn.Credential
}

func (u webUser) WebAuthnID() []byte                         { return []byte(u.User.ID) }
func (u webUser) WebAuthnName() string                       { return u.User.Login }
func (u webUser) WebAuthnDisplayName() string                { return u.User.DisplayName }
func (u webUser) WebAuthnCredentials() []webauthn.Credential { return u.Credentials }
func (s *Server) webUser(r *http.Request, id string) (webUser, error) {
	u, err := s.Store.User(r.Context(), id)
	if err != nil || !u.Active() {
		return webUser{}, application.ErrForbidden
	}
	raw, err := s.Store.WebAuthnCredentials(r.Context(), id)
	if err != nil {
		return webUser{}, err
	}
	v := webUser{User: u}
	for _, data := range raw {
		var c webauthn.Credential
		if err = json.Unmarshal(data, &c); err != nil {
			return v, err
		}
		v.Credentials = append(v.Credentials, c)
	}
	return v, nil
}
func (s *Server) totpBegin(w http.ResponseWriter, r *http.Request) {
	p := Principal(r.Context())
	if p.TokenID != "" {
		Fail(w, application.ErrForbidden)
		return
	}
	u, err := s.Store.User(r.Context(), p.UserID)
	if err != nil {
		Fail(w, err)
		return
	}
	if u.TOTPEnabled {
		Fail(w, errors.New("TOTP уже настроен. Отвязка доступна в списке факторов, для замены выберите «Заменить TOTP»"))
		return
	}
	secret := security.NewTOTPSecret()
	if err = s.Redis.Set(r.Context(), "totp-enroll:"+p.UserID, s.Cipher.Seal(secret), 5*time.Minute).Err(); err != nil {
		Fail(w, err)
		return
	}
	JSON(w, 200, map[string]string{"secret": secret, "uri": "otpauth://totp/Heimdall:" + url.PathEscape(p.Login) + "?issuer=Heimdall&algorithm=SHA1&digits=6&period=30&secret=" + secret})
}
func (s *Server) personalFactorPolicy(w http.ResponseWriter, r *http.Request) {
	var v struct {
		Policy string `json:"policy"`
	}
	if !Decode(w, r, &v) {
		return
	}
	p := Principal(r.Context())
	op, err := s.Store.SetPersonalFactorPolicy(r.Context(), p, v.Policy)
	if err == nil {
		err = s.newSession(w, r, p.UserID)
	}
	operation(w, op, err)
}
func (s *Server) totpFinish(w http.ResponseWriter, r *http.Request) {
	p := Principal(r.Context())
	if p.TokenID != "" {
		Fail(w, application.ErrForbidden)
		return
	}
	var v struct {
		Code string `json:"code"`
	}
	if !Decode(w, r, &v) {
		return
	}
	if !s.limited(r, "totp-enroll") {
		JSON(w, 429, nil)
		return
	}
	encrypted, err := s.Redis.Get(r.Context(), "totp-enroll:"+p.UserID).Result()
	if err != nil {
		JSON(w, 400, map[string]string{"error": "Начните регистрацию TOTP заново"})
		return
	}
	secret, err := s.Cipher.Open(encrypted)
	if _, ok := security.VerifyTOTP(secret, v.Code, time.Now()); err != nil || !ok {
		JSON(w, 400, map[string]string{"error": "Неверный код"})
		return
	}
	codes, hashes := recoveryCodes()
	if err = s.Store.EnableTOTP(r.Context(), p.UserID, encrypted, hashes); err != nil {
		Fail(w, err)
		return
	}
	s.Redis.Del(r.Context(), "totp-enroll:"+p.UserID)
	if err = s.newSession(w, r, p.UserID); err != nil {
		Fail(w, err)
		return
	}
	JSON(w, 200, map[string]any{"ok": true, "recovery_codes": codes})
}
func (s *Server) registrationBegin(w http.ResponseWriter, r *http.Request) {
	p := Principal(r.Context())
	if p.TokenID != "" {
		Fail(w, application.ErrForbidden)
		return
	}
	u, err := s.webUser(r, p.UserID)
	if err != nil {
		Fail(w, err)
		return
	}
	options, data, err := s.WebAuthn.BeginRegistration(u, webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{UserVerification: protocol.VerificationRequired}))
	if err != nil {
		Fail(w, err)
		return
	}
	raw, _ := json.Marshal(data)
	if err = s.Redis.Set(r.Context(), "webauthn-register:"+p.UserID, raw, 5*time.Minute).Err(); err != nil {
		Fail(w, err)
		return
	}
	JSON(w, 200, options)
}
func (s *Server) registrationFinish(w http.ResponseWriter, r *http.Request) {
	p := Principal(r.Context())
	if p.TokenID != "" {
		Fail(w, application.ErrForbidden)
		return
	}
	raw, err := s.Redis.GetDel(r.Context(), "webauthn-register:"+p.UserID).Bytes()
	var data webauthn.SessionData
	if err != nil || json.Unmarshal(raw, &data) != nil {
		JSON(w, 400, nil)
		return
	}
	u, err := s.webUser(r, p.UserID)
	if err != nil {
		Fail(w, err)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 65536)
	credential, err := s.WebAuthn.FinishRegistration(u, data, r)
	if err != nil {
		JSON(w, 400, map[string]string{"error": "Проверка WebAuthn не пройдена"})
		return
	}
	encoded, _ := json.Marshal(credential)
	codes, hashes := recoveryCodes()
	if err = s.Store.EnableWebAuthn(r.Context(), p.UserID, base64.RawURLEncoding.EncodeToString(credential.ID), encoded, hashes); err != nil {
		Fail(w, err)
		return
	}
	if err = s.newSession(w, r, p.UserID); err != nil {
		Fail(w, err)
		return
	}
	JSON(w, 200, map[string]any{"ok": true, "recovery_codes": codes})
}
func recoveryCodes() ([]string, []string) {
	codes := make([]string, 10)
	hashes := make([]string, 10)
	for i := range codes {
		codes[i] = "lnr_" + security.Random(20)
		hashes[i] = security.HashToken(codes[i])
	}
	return codes, hashes
}

type passkeyChallenge struct {
	UserID  string               `json:"user_id"`
	Version int64                `json:"version"`
	Data    webauthn.SessionData `json:"data"`
}

func (s *Server) passkeyBegin(w http.ResponseWriter, r *http.Request) {
	if !s.browserRequest(r) {
		JSON(w, 403, nil)
		return
	}
	var v struct {
		Login string `json:"login"`
	}
	if !Decode(w, r, &v) {
		return
	}
	if !s.limited(r, v.Login) {
		JSON(w, 429, nil)
		return
	}
	a, err := s.Store.Auth(r.Context(), v.Login)
	if err != nil {
		JSON(w, 401, map[string]string{"error": "Вход недоступен"})
		return
	}
	u, err := s.webUser(r, a.User.ID)
	if err != nil || len(u.Credentials) == 0 {
		JSON(w, 401, map[string]string{"error": "Вход недоступен"})
		return
	}
	options, data, err := s.WebAuthn.BeginLogin(u, webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		Fail(w, err)
		return
	}
	challenge := security.Random(32)
	raw, _ := json.Marshal(passkeyChallenge{u.User.ID, u.User.AuthVersion, *data})
	if err = s.Redis.Set(r.Context(), "webauthn-login:"+security.HashToken(challenge), raw, 5*time.Minute).Err(); err != nil {
		Fail(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "linpam_challenge", Value: challenge, Path: "/api/v1/auth/passkey", HttpOnly: true, Secure: !s.Config.Server.Development, SameSite: http.SameSiteStrictMode, MaxAge: 300})
	JSON(w, 200, options)
}
func (s *Server) passkeyFinish(w http.ResponseWriter, r *http.Request) {
	if !s.browserRequest(r) {
		JSON(w, 403, nil)
		return
	}
	cookie, err := r.Cookie("linpam_challenge")
	if err != nil {
		JSON(w, 401, nil)
		return
	}
	raw, err := s.Redis.GetDel(r.Context(), "webauthn-login:"+security.HashToken(cookie.Value)).Bytes()
	var data passkeyChallenge
	if err != nil || json.Unmarshal(raw, &data) != nil {
		JSON(w, 401, nil)
		return
	}
	u, err := s.webUser(r, data.UserID)
	if err != nil || u.User.AuthVersion != data.Version {
		JSON(w, 401, nil)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 65536)
	credential, err := s.WebAuthn.FinishLogin(u, data.Data, r)
	if err != nil || credential.Authenticator.CloneWarning {
		JSON(w, 401, map[string]string{"error": "Проверка passkey не пройдена"})
		return
	}
	encoded, _ := json.Marshal(credential)
	if err = s.Store.SaveWebAuthnCredential(r.Context(), u.User.ID, base64.RawURLEncoding.EncodeToString(credential.ID), encoded); err != nil {
		Fail(w, err)
		return
	}
	if err = s.newSession(w, r, u.User.ID); err != nil {
		Fail(w, err)
		return
	}
	JSON(w, 200, map[string]bool{"authenticated": true})
}
