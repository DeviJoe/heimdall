package httpapi

import (
	"Heimdall/internal/application"
	"Heimdall/internal/authorization"
	"Heimdall/internal/integrations"
	"Heimdall/internal/platform/config"
	"Heimdall/internal/platform/pki"
	"Heimdall/internal/platform/security"
	"Heimdall/internal/synchronization"
	"context"
	"encoding/json"
	"errors"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/redis/go-redis/v9"
	"golang.org/x/time/rate"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Server struct {
	FleetEvents *FleetEvents
	Store       application.ControlPlane
	Redis       *redis.Client
	Config      config.Config
	Authority   *pki.Authority
	Cipher      *security.Cipher
	WebAuthn    *webauthn.WebAuthn
	passwords   chan struct{}
	join        *rate.Limiter
}
type session struct {
	UserID          string    `json:"user_id"`
	Version         int64     `json:"version"`
	AuthenticatedAt time.Time `json:"authenticated_at"`
}
type contextKey struct{}

func Principal(ctx context.Context) authorization.Principal {
	p, _ := ctx.Value(contextKey{}).(authorization.Principal)
	return p
}
func JSON(w http.ResponseWriter, code int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	if value != nil {
		json.NewEncoder(w).Encode(value)
	}
}
func Decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		JSON(w, 400, map[string]string{"error": "Некорректный JSON"})
		return false
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		JSON(w, 400, map[string]string{"error": "Разрешён один JSON документ"})
		return false
	}
	return true
}
func Fail(w http.ResponseWriter, err error) {
	code := 400
	message := err.Error()
	var db *pgconn.PgError
	if errors.Is(err, application.ErrForbidden) {
		code = 403
		message = "Доступ запрещён"
	} else if errors.Is(err, application.ErrNotFound) {
		code = 404
		message = "Объект не найден"
	} else if errors.Is(err, application.ErrConflict) {
		code = 409
		message = "Данные уже изменены. Откройте актуальную версию перед сохранением"
	} else if errors.As(err, &db) {
		if db.Code == "23505" {
			code = 409
			message = "Идентификатор уже существует или был отозван"
		} else {
			code = 500
			message = "Ошибка хранилища"
			slog.Error("database request failed", "error", err)
		}
	}
	JSON(w, code, map[string]string{"error": message})
}
func New(store application.ControlPlane, redisClient *redis.Client, c config.Config, a *pki.Authority, cipher *security.Cipher) (*Server, error) {
	u, err := url.Parse(c.Server.PublicURL)
	if err != nil {
		return nil, err
	}
	wa, err := webauthn.New(&webauthn.Config{RPDisplayName: "Heimdall", RPID: u.Hostname(), RPOrigins: []string{c.Server.PublicURL}})
	if err != nil {
		return nil, err
	}
	return &Server{Store: store, Redis: redisClient, Config: c, Authority: a, Cipher: cipher, WebAuthn: wa, passwords: make(chan struct{}, 4), join: rate.NewLimiter(10, 20)}, nil
}
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/events/fleet", s.auth(s.fleetEvents))
	mux.HandleFunc("GET /health/live", func(w http.ResponseWriter, r *http.Request) { JSON(w, 200, map[string]string{"status": "alive"}) })
	mux.HandleFunc("GET /health/ready", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if s.Store.Health(ctx) != nil || s.Redis.Ping(ctx).Err() != nil {
			JSON(w, 503, map[string]string{"status": "unavailable"})
			return
		}
		JSON(w, 200, map[string]string{"status": "ready"})
	})
	mux.HandleFunc("POST /api/v1/auth/login", s.login)
	mux.HandleFunc("POST /api/v1/auth/totp", s.loginTOTP)
	mux.HandleFunc("POST /api/v1/auth/invitation", s.invitation)
	mux.HandleFunc("POST /api/v1/auth/passkey/begin", s.passkeyBegin)
	mux.HandleFunc("POST /api/v1/auth/passkey/finish", s.passkeyFinish)
	mux.HandleFunc("POST /api/v1/agent/join", s.enroll)
	mux.HandleFunc("POST /api/v1/agent/recover", s.recoverNode)
	s.routes(mux)
	s.policyRoutes(mux)
	s.unixRoutes(mux)
	s.integrationRoutes(mux)
	mux.Handle("/mcp", s.mcpHandler())
	s.swaggerRoutes(mux)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("X-Frame-Options", "DENY")
		defer func() {
			if v := recover(); v != nil {
				slog.Error("request panic", "value", v)
				JSON(w, 500, map[string]string{"error": "Внутренняя ошибка"})
			}
		}()
		if r.URL.Path == "/mcp" || r.URL.Path == "/swagger" || r.URL.Path == "/api/v1/openapi.json" {
			settings, err := s.Store.Settings(r.Context())
			if err != nil {
				Fail(w, err)
				return
			}
			if (r.URL.Path == "/mcp" && (!s.Config.MCP.Enabled || !settings.MCPEnabled)) || (r.URL.Path != "/mcp" && (!s.Config.Swagger.Enabled || !settings.SwaggerEnabled)) {
				http.NotFound(w, r)
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}
func (s *Server) auth(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, err := s.authenticate(r, "api")
		if err != nil {
			JSON(w, 401, map[string]string{"error": "Войдите в систему"})
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" && p.TokenID == "" {
			if !s.browserRequest(r) {
				JSON(w, 403, map[string]string{"error": "Проверка CSRF не пройдена"})
				return
			}
		}
		handler(w, r.WithContext(context.WithValue(r.Context(), contextKey{}, p)))
	}
}
func (s *Server) browserRequest(r *http.Request) bool {
	return (r.Header.Get("X-Heimdall-CSRF") == "1" || r.Header.Get("X-LinPam-CSRF") == "1") && (r.Header.Get("Origin") == "" || r.Header.Get("Origin") == s.Config.Server.PublicURL)
}
func (s *Server) authenticate(r *http.Request, audience string) (authorization.Principal, error) {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return s.Store.Bearer(r.Context(), strings.TrimPrefix(h, "Bearer "), audience)
	}
	if audience != "api" {
		return authorization.Principal{}, application.ErrForbidden
	}
	cookie, err := r.Cookie("linpam_session")
	if err != nil {
		return authorization.Principal{}, err
	}
	var v session
	data, err := s.Redis.Get(r.Context(), "session:"+security.HashToken(cookie.Value)).Bytes()
	if err != nil || json.Unmarshal(data, &v) != nil {
		return authorization.Principal{}, application.ErrForbidden
	}
	p, err := s.Store.Principal(r.Context(), v.UserID, "", "api")
	if err != nil || p.AuthVersion != v.Version {
		return p, application.ErrForbidden
	}
	return p, nil
}
func (s *Server) newSession(w http.ResponseWriter, r *http.Request, id string) error {
	user, err := s.Store.User(r.Context(), id)
	if err != nil {
		return err
	}
	if user.Kind == "service" {
		return application.ErrForbidden
	}
	p, err := s.Store.Principal(r.Context(), id, "", "api")
	if err != nil {
		return err
	}
	token := security.Random(32)
	v := session{UserID: id, Version: p.AuthVersion, AuthenticatedAt: time.Now()}
	data, _ := json.Marshal(v)
	if err = s.Redis.Set(r.Context(), "session:"+security.HashToken(token), data, 8*time.Hour).Err(); err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{Name: "linpam_session", Value: token, Path: "/", HttpOnly: true, Secure: !s.Config.Server.Development, SameSite: http.SameSiteStrictMode, MaxAge: 28800})
	return nil
}
func (s *Server) limited(r *http.Request, login string) bool {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	key := "auth-limit:" + security.HashToken(ip+":"+login)
	script := redis.NewScript(`local n=redis.call('INCR',KEYS[1]);if n==1 then redis.call('EXPIRE',KEYS[1],60) end;return n`)
	n, err := script.Run(r.Context(), s.Redis, []string{key}).Int()
	return err == nil && n <= 10
}
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !s.browserRequest(r) {
		JSON(w, 403, map[string]string{"error": "CSRF"})
		return
	}
	var v struct {
		Login    string `json:"login"`
		Password string `json:"password"`
		Provider string `json:"provider"`
	}
	if !Decode(w, r, &v) {
		return
	}
	if !s.limited(r, v.Login) {
		JSON(w, 429, map[string]string{"error": "Подождите минуту перед следующей попыткой"})
		return
	}
	select {
	case s.passwords <- struct{}{}:
		defer func() { <-s.passwords }()
	default:
		JSON(w, 429, map[string]string{"error": "Вход временно занят"})
		return
	}
	var a application.AuthRecord
	var err error
	valid := false
	if v.Provider != "" {
		for _, provider := range s.Config.LDAP {
			if provider.ID == v.Provider {
				subject, e := integrations.LDAPLogin(provider, v.Login, v.Password)
				if e == nil {
					u, e := s.Store.IdentityUser(r.Context(), "ldap:"+provider.ID, subject)
					if e == nil {
						a, err = s.Store.Auth(r.Context(), u.Login)
						valid = err == nil
					}
				}
				break
			}
		}
	} else {
		a, err = s.Store.Auth(r.Context(), v.Login)
		valid = err == nil && len(v.Password) <= 1024 && security.VerifyPassword(a.PasswordHash, v.Password)
	}
	if !valid {
		JSON(w, 401, map[string]string{"error": "Неверный логин или пароль"})
		return
	}
	if a.User.MFAEnabled {
		factors, err := s.Store.FactorState(r.Context(), a.User.ID)
		if err != nil {
			Fail(w, err)
			return
		}
		challenge := security.Random(32)
		data, _ := json.Marshal(session{UserID: a.User.ID, Version: a.User.AuthVersion})
		if err = s.Redis.Set(r.Context(), "login-challenge:"+security.HashToken(challenge), data, 5*time.Minute).Err(); err != nil {
			Fail(w, err)
			return
		}
		JSON(w, 200, map[string]any{"totp_required": factors.TOTP, "passkey_required": !factors.TOTP && factors.Passkey, "challenge": challenge})
		return
	}
	if err = s.newSession(w, r, a.User.ID); err != nil {
		Fail(w, err)
		return
	}
	JSON(w, 200, map[string]any{"authenticated": true, "mfa_required": a.User.RequireMFA})
}
func (s *Server) loginTOTP(w http.ResponseWriter, r *http.Request) {
	if !s.browserRequest(r) {
		JSON(w, 403, nil)
		return
	}
	var v struct {
		Challenge string `json:"challenge"`
		Code      string `json:"code"`
	}
	if !Decode(w, r, &v) {
		return
	}
	if !s.limited(r, "totp") {
		JSON(w, 429, nil)
		return
	}
	data, err := s.Redis.Get(r.Context(), "login-challenge:"+security.HashToken(v.Challenge)).Bytes()
	var challenge session
	if err != nil || json.Unmarshal(data, &challenge) != nil {
		JSON(w, 401, nil)
		return
	}
	u, err := s.Store.User(r.Context(), challenge.UserID)
	if err != nil || u.AuthVersion != challenge.Version {
		JSON(w, 401, nil)
		return
	}
	a, err := s.Store.Auth(r.Context(), u.Login)
	if err != nil {
		JSON(w, 401, nil)
		return
	}
	valid := false
	if strings.HasPrefix(v.Code, "lnr_") {
		valid = s.Store.ConsumeRecoveryCode(r.Context(), u.ID, v.Code)
	} else {
		secret, e := s.Cipher.Open(a.TOTPSecret)
		step, ok := security.VerifyTOTP(secret, v.Code, time.Now())
		valid = e == nil && ok && s.Store.UseTOTP(r.Context(), u.ID, step)
	}
	if !valid {
		JSON(w, 401, map[string]string{"error": "Неверный или уже использованный код"})
		return
	}
	if _, err = s.Redis.GetDel(r.Context(), "login-challenge:"+security.HashToken(v.Challenge)).Result(); err != nil {
		JSON(w, 401, nil)
		return
	}
	if err = s.newSession(w, r, u.ID); err != nil {
		Fail(w, err)
		return
	}
	JSON(w, 200, map[string]bool{"authenticated": true})
}
func (s *Server) invitation(w http.ResponseWriter, r *http.Request) {
	if !s.browserRequest(r) {
		JSON(w, 403, nil)
		return
	}
	var v struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if !Decode(w, r, &v) {
		return
	}
	if !s.limited(r, "invite") {
		JSON(w, 429, nil)
		return
	}
	select {
	case s.passwords <- struct{}{}:
		defer func() { <-s.passwords }()
	default:
		JSON(w, 429, nil)
		return
	}
	hash, err := security.PasswordHash(v.Password)
	if err != nil {
		Fail(w, err)
		return
	}
	u, err := s.Store.AcceptInvite(r.Context(), v.Token, hash)
	if err != nil {
		Fail(w, err)
		return
	}
	if err = s.newSession(w, r, u.ID); err != nil {
		Fail(w, err)
		return
	}
	JSON(w, 200, map[string]any{"authenticated": true, "mfa_required": u.RequireMFA})
}
func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	if !s.join.Allow() {
		JSON(w, 429, nil)
		return
	}
	var v struct {
		Token          string `json:"token"`
		Name           string `json:"name"`
		CSR            []byte `json:"csr"`
		BootstrapNonce string `json:"bootstrap_nonce"`
	}
	if !Decode(w, r, &v) {
		return
	}
	if strings.TrimSpace(v.Name) == "" || len(v.Name) > 120 {
		JSON(w, 400, nil)
		return
	}
	id := newID()
	settings, err := s.Store.Settings(r.Context())
	if err != nil {
		Fail(w, err)
		return
	}
	ttl := settings.NodeCertificateTTLSeconds
	if ttl == 0 {
		ttl = synchronization.DefaultNodeCertificateTTLSeconds
	}
	cert, parsed, err := s.Authority.Issue(id, v.CSR, time.Duration(ttl)*time.Second)
	if err != nil {
		JSON(w, 400, map[string]string{"error": "Invalid CSR"})
		return
	}
	if _, err = s.Store.EnrollBound(r.Context(), v.Token, v.Name, parsed.SerialNumber.String(), parsed.NotAfter, id, v.BootstrapNonce); err != nil {
		Fail(w, err)
		return
	}
	JSON(w, 201, map[string]any{"node_id": id, "certificate": cert})
}
func allowed(w http.ResponseWriter, r *http.Request, permission, group string) bool {
	if !Principal(r.Context()).Allowed(permission, group) {
		Fail(w, application.ErrForbidden)
		return false
	}
	return true
}
func result(w http.ResponseWriter, value any, err error) {
	if err != nil {
		Fail(w, err)
		return
	}
	JSON(w, 200, value)
}
func operation(w http.ResponseWriter, id string, err error) {
	result(w, map[string]string{"operation_id": id}, err)
}
