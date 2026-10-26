package httpapi

import (
	"Heimdall/internal/application"
	"Heimdall/internal/platform/config"
	"Heimdall/internal/platform/security"
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

type oauthFlow struct {
	Provider, UserID, SessionHash, Verifier, Nonce, Browser string
	Version                                                 int64
	Link                                                    bool
}

func (s *Server) provider(id string) (config.OIDCProvider, bool) {
	if id == "telegram" && s.Config.Telegram.Enabled {
		return config.OIDCProvider{ID: id, Issuer: "https://oauth.telegram.org", ClientIDEnv: s.Config.Telegram.ClientIDEnv, ClientSecretEnv: s.Config.Telegram.ClientSecretEnv}, true
	}
	for _, p := range s.Config.OIDC {
		if p.ID == id {
			return p, true
		}
	}
	return config.OIDCProvider{}, false
}
func (s *Server) integrationRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/integrations/status", s.auth(func(w http.ResponseWriter, r *http.Request) {
		v, err := s.Store.IntegrationStatuses(r.Context(), Principal(r.Context()))
		result(w, v, err)
	}))
	mux.HandleFunc("GET /api/v1/auth/providers", func(w http.ResponseWriter, r *http.Request) {
		out := []map[string]string{}
		for _, p := range s.Config.OIDC {
			out = append(out, map[string]string{"id": p.ID, "type": "oidc"})
		}
		for _, p := range s.Config.LDAP {
			out = append(out, map[string]string{"id": p.ID, "type": "ldap"})
		}
		JSON(w, 200, out)
	})
	mux.HandleFunc("POST /api/v1/identities", s.auth(func(w http.ResponseWriter, r *http.Request) {
		var v struct {
			Provider string `json:"provider"`
			Subject  string `json:"subject"`
			UserID   string `json:"user_id"`
		}
		if !Decode(w, r, &v) {
			return
		}
		provider, ok := s.provider(v.Provider)
		if !ok || v.Provider == "telegram" {
			JSON(w, 400, map[string]string{"error": "Choose a configured OIDC provider"})
			return
		}
		err := s.Store.LinkIdentity(r.Context(), Principal(r.Context()), "oidc:"+provider.Issuer, v.Subject, v.UserID)
		result(w, map[string]bool{"ok": true}, err)
	}))
	mux.HandleFunc("GET /api/v1/notifications", s.auth(func(w http.ResponseWriter, r *http.Request) {
		v, err := s.Store.Notifications(r.Context(), Principal(r.Context()))
		result(w, v, err)
	}))
	mux.HandleFunc("DELETE /api/v1/notifications/{id}", s.auth(func(w http.ResponseWriter, r *http.Request) {
		err := s.Store.UnlinkNotification(r.Context(), Principal(r.Context()), r.PathValue("id"))
		result(w, map[string]bool{"ok": true}, err)
	}))
	mux.HandleFunc("GET /api/v1/auth/oidc/{provider}/start", s.oauthStart)
	mux.HandleFunc("POST /api/v1/me/notifications/{provider}/start", s.auth(s.oauthStart))
	mux.HandleFunc("GET /api/v1/auth/oidc/{provider}/callback", s.oauthCallback)
	if s.Config.Telegram.Enabled {
		mux.HandleFunc("POST /api/v1/integrations/telegram/webhook", s.telegramWebhook)
	}
}
func (s *Server) oauthConfig(ctx context.Context, id string) (oauth2.Config, *oidc.Provider, error) {
	redirect := s.Config.Server.PublicURL + "/api/v1/auth/oidc/" + id + "/callback"
	if id == "mattermost" && s.Config.Mattermost.Enabled {
		c := s.Config.Mattermost
		return oauth2.Config{ClientID: os.Getenv(c.ClientIDEnv), ClientSecret: os.Getenv(c.ClientSecretEnv), RedirectURL: redirect, Endpoint: oauth2.Endpoint{AuthURL: strings.TrimRight(c.URL, "/") + "/oauth/authorize", TokenURL: strings.TrimRight(c.URL, "/") + "/oauth/access_token"}}, nil, nil
	}
	p, ok := s.provider(id)
	if !ok {
		return oauth2.Config{}, nil, errors.New("provider unavailable")
	}
	provider, err := oidc.NewProvider(ctx, p.Issuer)
	if err != nil {
		return oauth2.Config{}, nil, err
	}
	scopes := []string{"openid", "profile"}
	if id == "telegram" {
		scopes = append(scopes, "telegram:bot_access")
	}
	return oauth2.Config{ClientID: os.Getenv(p.ClientIDEnv), ClientSecret: os.Getenv(p.ClientSecretEnv), RedirectURL: redirect, Endpoint: provider.Endpoint(), Scopes: scopes}, provider, nil
}
func (s *Server) oauthStart(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("provider")
	flow := oauthFlow{Provider: id, Verifier: oauth2.GenerateVerifier(), Nonce: security.Random(32), Browser: security.Random(32), Link: r.Method == "POST"}
	if id == "telegram" || id == "mattermost" {
		if !flow.Link {
			Fail(w, application.ErrForbidden)
			return
		}
	}
	if flow.Link {
		p := Principal(r.Context())
		if !p.Self(p.UserID) || p.TokenID != "" {
			Fail(w, application.ErrForbidden)
			return
		}
		cookie, err := r.Cookie("linpam_session")
		if err != nil {
			Fail(w, application.ErrForbidden)
			return
		}
		flow.UserID = p.UserID
		flow.Version = p.AuthVersion
		flow.SessionHash = security.HashToken(cookie.Value)
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	conf, _, err := s.oauthConfig(ctx, id)
	if err != nil {
		JSON(w, 503, map[string]string{"error": "Провайдер авторизации недоступен"})
		return
	}
	state := security.Random(32)
	data, _ := json.Marshal(flow)
	if err = s.Redis.Set(ctx, "oauth-state:"+security.HashToken(state), data, 5*time.Minute).Err(); err != nil {
		Fail(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "linpam_oauth", Value: flow.Browser, Path: "/api/v1/auth/oidc/", HttpOnly: true, Secure: !s.Config.Server.Development, SameSite: http.SameSiteLaxMode, MaxAge: 300})
	target := conf.AuthCodeURL(state, oauth2.S256ChallengeOption(flow.Verifier), oidc.Nonce(flow.Nonce))
	if flow.Link {
		JSON(w, 200, map[string]string{"url": target})
	} else {
		http.Redirect(w, r, target, 303)
	}
}
func (s *Server) oauthCallback(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	state := r.URL.Query().Get("state")
	data, err := s.Redis.GetDel(ctx, "oauth-state:"+security.HashToken(state)).Bytes()
	var flow oauthFlow
	cookie, cookieErr := r.Cookie("linpam_oauth")
	if err != nil || json.Unmarshal(data, &flow) != nil || cookieErr != nil || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(flow.Browser)) != 1 || flow.Provider != r.PathValue("provider") {
		JSON(w, 400, map[string]string{"error": "OIDC state invalid or expired"})
		return
	}
	conf, provider, err := s.oauthConfig(ctx, flow.Provider)
	if err != nil {
		JSON(w, 503, nil)
		return
	}
	token, err := conf.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(flow.Verifier))
	if err != nil {
		JSON(w, 401, map[string]string{"error": "OIDC exchange failed"})
		return
	}
	subject := ""
	oidcIssuer := ""
	remoteLogin := ""
	remoteName := ""
	chatID := ""
	if flow.Provider == "mattermost" {
		client := conf.Client(ctx, token)
		remote, err := remoteJSON(ctx, client, "GET", strings.TrimRight(s.Config.Mattermost.URL, "/")+"/api/v4/users/me", nil, "")
		if err != nil {
			JSON(w, 401, nil)
			return
		}
		subject, _ = remote["id"].(string)
		chatID = subject
	} else {
		raw, ok := token.Extra("id_token").(string)
		if !ok {
			JSON(w, 401, nil)
			return
		}
		verified, err := provider.Verifier(&oidc.Config{ClientID: conf.ClientID}).Verify(ctx, raw)
		if err != nil || verified.Nonce != flow.Nonce {
			JSON(w, 401, map[string]string{"error": "OIDC token verification failed"})
			return
		}
		subject = verified.Subject
		oidcIssuer = verified.Issuer
		var profile struct {
			Login string `json:"preferred_username"`
			Name  string `json:"name"`
		}
		if verified.Claims(&profile) == nil {
			remoteLogin = profile.Login
			remoteName = profile.Name
		}
		if flow.Provider == "telegram" {
			var claims struct {
				ID json.Number `json:"id"`
			}
			if verified.Claims(&claims) != nil {
				JSON(w, 401, nil)
				return
			}
			n, e := claims.ID.Int64()
			if e != nil || n <= 0 {
				JSON(w, 401, nil)
				return
			}
			chatID = strconv.FormatInt(n, 10)
			subject = chatID
		}
	}
	if subject == "" {
		JSON(w, 401, nil)
		return
	}
	if flow.Link {
		stored, err := s.Redis.Get(ctx, "session:"+flow.SessionHash).Bytes()
		var sessionData session
		if err != nil || json.Unmarshal(stored, &sessionData) != nil || sessionData.UserID != flow.UserID || sessionData.Version != flow.Version {
			JSON(w, 401, nil)
			return
		}
		p, err := s.Store.Principal(ctx, flow.UserID, "", "api")
		if err != nil || p.AuthVersion != flow.Version || !p.Self(flow.UserID) {
			JSON(w, 401, nil)
			return
		}
		if err = s.Store.LinkNotification(ctx, flow.UserID, flow.Provider, subject, chatID); err != nil {
			Fail(w, err)
			return
		}
	} else {
		u, err := s.Store.IdentityUser(ctx, "oidc:"+oidcIssuer, subject)
		if err != nil {
			if provider, ok := s.provider(flow.Provider); ok && provider.AutoProvision {
				u, err = s.Store.ProvisionOIDC(ctx, oidcIssuer, subject, remoteLogin, remoteName, provider.RequireMFA)
			}
		}
		if err != nil {
			JSON(w, 403, map[string]string{"error": "Identity is not assigned to an active Heimdall user"})
			return
		}
		if u.MFAEnabled {
			a, err := s.Store.Auth(ctx, u.Login)
			if err != nil {
				JSON(w, 401, nil)
				return
			}
			if a.TOTPSecret != "" {
				challenge := security.Random(32)
				raw, _ := json.Marshal(session{UserID: u.ID, Version: u.AuthVersion})
				s.Redis.Set(ctx, "login-challenge:"+security.HashToken(challenge), raw, 5*time.Minute)
				http.Redirect(w, r, "/#totp="+challenge, 303)
				return
			}
			http.Redirect(w, r, "/#passkey="+u.Login, 303)
			return
		}
		if err = s.newSession(w, r, u.ID); err != nil {
			Fail(w, err)
			return
		}
	}
	http.Redirect(w, r, "/", 303)
}
func remoteJSON(ctx context.Context, c *http.Client, method, url string, body any, bearer string) (map[string]any, error) {
	var reader io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("provider HTTP %d", response.StatusCode)
	}
	var out map[string]any
	err = json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&out)
	return out, err
}
func (s *Server) telegramWebhook(w http.ResponseWriter, r *http.Request) {
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Telegram-Bot-Api-Secret-Token")), []byte(os.Getenv(s.Config.Telegram.WebhookSecretEnv))) != 1 {
		JSON(w, 403, nil)
		return
	}
	var update struct {
		ID      int64 `json:"update_id"`
		Message struct {
			Text string `json:"text"`
			From struct {
				ID int64 `json:"id"`
			} `json:"from"`
			Chat struct {
				ID   int64  `json:"id"`
				Type string `json:"type"`
			} `json:"chat"`
		} `json:"message"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 65536)
	if json.NewDecoder(r.Body).Decode(&update) != nil {
		JSON(w, 400, nil)
		return
	}
	if update.Message.Chat.Type != "private" || update.Message.Chat.ID != update.Message.From.ID {
		JSON(w, 200, map[string]bool{"ok": true})
		return
	}
	p, err := s.Store.TelegramPrincipal(r.Context(), strconv.FormatInt(update.Message.From.ID, 10))
	if err != nil {
		JSON(w, 200, map[string]bool{"ok": true})
		return
	}
	fresh, err := s.Store.TelegramUpdate(r.Context(), update.ID)
	if err != nil {
		JSON(w, 503, nil)
		return
	}
	if fresh && (update.Message.Text == "/start" || update.Message.Text == "/status") {
		incidents, err := s.Store.Incidents(r.Context(), p)
		if err == nil {
			count := 0
			for _, i := range incidents {
				if i.Status != "resolved" {
					count++
				}
			}
			client := &http.Client{Timeout: 10 * time.Second}
			_, err = remoteJSON(r.Context(), client, "POST", "https://api.telegram.org/bot"+os.Getenv(s.Config.Telegram.BotTokenEnv)+"/sendMessage", map[string]any{"chat_id": update.Message.Chat.ID, "text": fmt.Sprintf("Heimdall: %s\nАктивных доступных вам инцидентов: %d\n%s", p.Login, count, s.Config.Server.PublicURL)}, "")
		}
	}
	JSON(w, 200, map[string]bool{"ok": true})
}
