package httpapi

import (
	"Heimdall/internal/application"
	"Heimdall/internal/authorization"
	"Heimdall/internal/credentials"
	"Heimdall/internal/fleet"
	"Heimdall/internal/identity"
	"Heimdall/internal/platform/security"
	"github.com/google/uuid"
	"net/http"
	"strconv"
	"time"
)

func newID() string { return uuid.NewString() }
func (s *Server) routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/access/graph", s.auth(s.accessGraph))
	mux.HandleFunc("GET /api/v1/documentation", s.auth(s.documentationList))
	mux.HandleFunc("GET /api/v1/documentation/{slug}", s.auth(s.documentationRead))
	mux.HandleFunc("PUT /api/v1/documentation/{slug}", s.auth(s.documentationSave))
	mux.HandleFunc("GET /api/v1/me/native-policy", s.auth(s.nativeAccessPolicy))
	mux.HandleFunc("GET /api/v1/users/{id}/native-policy", s.auth(s.nativeAccessPolicy))
	mux.HandleFunc("POST /api/v1/me/totp/rotate/begin", s.auth(s.totpRotateBegin))
	mux.HandleFunc("POST /api/v1/me/totp/rotate/finish", s.auth(s.totpRotateFinish))
	mux.HandleFunc("GET /api/v1/me/nodes", s.auth(s.accessibleNodes))
	mux.HandleFunc("GET /api/v1/users/{id}/nodes", s.auth(s.accessibleNodes))
	mux.HandleFunc("GET /api/v1/summary", s.auth(func(w http.ResponseWriter, r *http.Request) {
		settings, err := s.Store.Settings(r.Context())
		if err != nil {
			Fail(w, err)
			return
		}
		v, err := s.Store.FleetSummary(r.Context(), Principal(r.Context()), time.Duration(settings.OfflineSeconds)*time.Second)
		result(w, v, err)
	}))
	mux.HandleFunc("GET /api/v1/me", s.auth(func(w http.ResponseWriter, r *http.Request) {
		p := Principal(r.Context())
		u, err := s.Store.User(r.Context(), p.UserID)
		factors, fe := s.Store.FactorState(r.Context(), p.UserID)
		if fe != nil {
			Fail(w, fe)
			return
		}
		settings, se := s.Store.Settings(r.Context())
		if se != nil {
			Fail(w, se)
			return
		}
		requiredSK, errSK := s.Store.RequireSK(r.Context(), p.UserID)
		if errSK != nil {
			Fail(w, errSK)
			return
		}
		result(w, map[string]any{"user": u, "factor_state": factors, "principal": p, "permissions": authorization.Permissions, "require_sk": requiredSK, "key_ttl_seconds": settings.KeyTTLSeconds, "telegram_enabled": s.Config.Telegram.Enabled, "mattermost_enabled": s.Config.Mattermost.Enabled, "swagger_enabled": s.Config.Swagger.Enabled && settings.SwaggerEnabled, "mcp_enabled": s.Config.MCP.Enabled && settings.MCPEnabled}, err)
	}))
	mux.HandleFunc("POST /api/v1/auth/logout", s.auth(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("linpam_session"); err == nil {
			s.Redis.Del(r.Context(), "session:"+security.HashToken(c.Value))
		}
		http.SetCookie(w, &http.Cookie{Name: "linpam_session", Value: "", Path: "/", HttpOnly: true, Secure: !s.Config.Server.Development, SameSite: http.SameSiteStrictMode, MaxAge: -1})
		JSON(w, 200, map[string]bool{"ok": true})
	}))
	mux.HandleFunc("GET /api/v1/users", s.auth(func(w http.ResponseWriter, r *http.Request) {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		var v []identity.User
		var next string
		var err error
		if unix := r.URL.Query().Get("unix_group"); unix != "" {
			v, next, err = s.Store.QueryUnixUsersPage(r.Context(), Principal(r.Context()), limit, r.URL.Query().Get("after"), r.URL.Query().Get("query"), unix, r.URL.Query().Get("members") == "true")
		} else if r.URL.Query().Get("status") != "" || r.URL.Query().Get("unix_sync") != "" {
			v, next, err = s.Store.FilteredUsersPage(r.Context(), Principal(r.Context()), limit, r.URL.Query().Get("after"), r.URL.Query().Get("query"), r.URL.Query().Get("kind"), r.URL.Query().Get("people_group"), r.URL.Query().Get("factor"), r.URL.Query().Get("status"), r.URL.Query().Get("unix_sync"))
		} else {
			v, next, err = s.Store.QueryUsersPage(r.Context(), Principal(r.Context()), limit, r.URL.Query().Get("after"), r.URL.Query().Get("query"), r.URL.Query().Get("kind"), r.URL.Query().Get("people_group"), r.URL.Query().Get("factor"))
		}
		w.Header().Set("X-Heimdall-Next-Cursor", next)
		result(w, v, err)
	}))
	mux.HandleFunc("POST /api/v1/users", s.auth(func(w http.ResponseWriter, r *http.Request) {
		var u identity.User
		if !Decode(w, r, &u) {
			return
		}
		token := security.Random(32)
		u, op, err := s.Store.CreateUser(r.Context(), Principal(r.Context()), u, security.HashToken(token))
		if err != nil {
			Fail(w, err)
			return
		}
		invitationURL := ""
		if u.Kind != "service" {
			invitationURL = s.Config.Server.PublicURL + "/invite#" + token
		}
		JSON(w, 201, map[string]any{"user": u, "operation_id": op, "invitation_url": invitationURL})
	}))
	mux.HandleFunc("PUT /api/v1/users/{id}", s.auth(func(w http.ResponseWriter, r *http.Request) {
		var v struct {
			identity.User
			Maintenance bool `json:"maintenance"`
		}
		if !Decode(w, r, &v) {
			return
		}
		v.User.ID = r.PathValue("id")
		p := Principal(r.Context())
		op, err := s.Store.UpdateUser(r.Context(), p, v.User, v.Maintenance)
		// Refresh only the browser session that confirmed its own profile change.
		// Other sessions still expire through auth_version; unmet enrollment
		// requirements are evaluated again by auth and restrict this session too.
		if err == nil && p.TokenID == "" && p.UserID == v.User.ID {
			err = s.newSession(w, r, p.UserID)
		}
		operation(w, op, err)
	}))
	mux.HandleFunc("POST /api/v1/users/{id}/status", s.auth(func(w http.ResponseWriter, r *http.Request) {
		var v struct {
			Status string `json:"status"`
		}
		if !Decode(w, r, &v) {
			return
		}
		op, err := s.Store.SetUserStatus(r.Context(), Principal(r.Context()), r.PathValue("id"), v.Status)
		operation(w, op, err)
	}))
	mux.HandleFunc("PUT /api/v1/users/{id}/linux-password", s.auth(func(w http.ResponseWriter, r *http.Request) {
		var v struct {
			Password string `json:"password"`
		}
		if !Decode(w, r, &v) {
			return
		}
		p := Principal(r.Context())
		if !p.Self(r.PathValue("id")) && !p.Allowed("users.manage", "*") {
			Fail(w, application.ErrForbidden)
			return
		}
		hash := ""
		var err error
		if v.Password != "" {
			hash, err = security.LinuxHash(v.Password)
			if err != nil {
				Fail(w, err)
				return
			}
		}
		op, err := s.Store.SetLinuxPassword(r.Context(), p, r.PathValue("id"), hash)
		operation(w, op, err)
	}))
	mux.HandleFunc("GET /api/v1/users/{id}/unix-groups", s.auth(s.collection("unix-memberships")))
	mux.HandleFunc("GET /api/v1/users/{id}/keys", s.auth(s.collection("keys")))
	mux.HandleFunc("POST /api/v1/users/{id}/keys", s.auth(func(w http.ResponseWriter, r *http.Request) {
		var v struct {
			Name      string `json:"name"`
			PublicKey string `json:"public_key"`
		}
		if !Decode(w, r, &v) {
			return
		}
		if len(v.Name) < 1 || len(v.Name) > 100 {
			JSON(w, 400, map[string]string{"error": "Введите название ключа"})
			return
		}
		settings, err := s.Store.Settings(r.Context())
		if err != nil {
			Fail(w, err)
			return
		}
		canonical, fp, alg, err := credentials.Parse(v.PublicKey, settings.RequireSK)
		if err != nil {
			Fail(w, err)
			return
		}
		key, op, err := s.Store.AddKey(r.Context(), Principal(r.Context()), credentials.Key{UserID: r.PathValue("id"), Name: v.Name, PublicKey: canonical, Fingerprint: fp, Algorithm: alg, ExpiresAt: time.Now().Add(time.Duration(settings.KeyTTLSeconds) * time.Second)})
		if err != nil {
			Fail(w, err)
			return
		}
		JSON(w, 201, map[string]any{"key": key, "operation_id": op})
	}))
	mux.HandleFunc("DELETE /api/v1/keys/{id}", s.auth(func(w http.ResponseWriter, r *http.Request) {
		op, err := s.Store.RevokeKey(r.Context(), Principal(r.Context()), r.PathValue("id"))
		operation(w, op, err)
	}))
	mux.HandleFunc("GET /api/v1/users/{id}/sync", s.auth(func(w http.ResponseWriter, r *http.Request) {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		v, next, err := s.Store.UserSyncPage(r.Context(), Principal(r.Context()), r.PathValue("id"), limit, r.URL.Query().Get("after"))
		w.Header().Set("X-Heimdall-Next-Cursor", next)
		result(w, v, err)
	}))
	mux.HandleFunc("GET /api/v1/roles", s.auth(s.collection("roles")))
	mux.HandleFunc("POST /api/v1/roles", s.auth(func(w http.ResponseWriter, r *http.Request) {
		var v authorization.Role
		if !Decode(w, r, &v) {
			return
		}
		op, err := s.Store.SaveRole(r.Context(), Principal(r.Context()), v)
		operation(w, op, err)
	}))
	mux.HandleFunc("GET /api/v1/users/{id}/bindings", s.auth(s.collection("bindings")))
	mux.HandleFunc("POST /api/v1/bindings", s.auth(func(w http.ResponseWriter, r *http.Request) {
		var v authorization.Binding
		if !Decode(w, r, &v) {
			return
		}
		op, err := s.Store.BindRole(r.Context(), Principal(r.Context()), v)
		operation(w, op, err)
	}))
	mux.HandleFunc("DELETE /api/v1/bindings/{id}", s.auth(func(w http.ResponseWriter, r *http.Request) {
		op, err := s.Store.UnbindRole(r.Context(), Principal(r.Context()), r.PathValue("id"))
		operation(w, op, err)
	}))
	mux.HandleFunc("GET /api/v1/groups", s.auth(s.collection("groups")))
	mux.HandleFunc("POST /api/v1/groups", s.auth(func(w http.ResponseWriter, r *http.Request) {
		var v fleet.Group
		if !Decode(w, r, &v) {
			return
		}
		if len(v.Name) < 1 || len(v.Name) > 120 {
			JSON(w, 400, nil)
			return
		}
		v.ID = newID()
		op, err := s.Store.SaveGroup(r.Context(), Principal(r.Context()), v)
		result(w, map[string]any{"group": v, "operation_id": op}, err)
	}))
	mux.HandleFunc("GET /api/v1/nodes", s.auth(func(w http.ResponseWriter, r *http.Request) {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		settings, err := s.Store.Settings(r.Context())
		if err != nil {
			Fail(w, err)
			return
		}
		var v []fleet.Node
		var next string
		if r.URL.Query().Get("status") != "" || r.URL.Query().Get("platform") != "" {
			v, next, err = s.Store.FilteredNodesPage(r.Context(), Principal(r.Context()), time.Duration(settings.OfflineSeconds)*time.Second, limit, r.URL.Query().Get("after"), r.URL.Query().Get("group_id"), r.URL.Query().Get("query"), r.URL.Query().Get("status"), r.URL.Query().Get("platform"))
		} else {
			v, next, err = s.Store.QueryNodesPage(r.Context(), Principal(r.Context()), time.Duration(settings.OfflineSeconds)*time.Second, limit, r.URL.Query().Get("after"), r.URL.Query().Get("group_id"), r.URL.Query().Get("query"))
		}
		w.Header().Set("X-Heimdall-Next-Cursor", next)
		result(w, v, err)
	}))
	mux.HandleFunc("PUT /api/v1/nodes/{id}", s.auth(func(w http.ResponseWriter, r *http.Request) {
		var v struct {
			GroupID  string `json:"group_id"`
			Disabled bool   `json:"disabled"`
		}
		if !Decode(w, r, &v) {
			return
		}
		op, err := s.Store.SetNode(r.Context(), Principal(r.Context()), r.PathValue("id"), v.GroupID, v.Disabled)
		operation(w, op, err)
	}))
	mux.HandleFunc("POST /api/v1/nodes/{id}/retry", s.auth(func(w http.ResponseWriter, r *http.Request) {
		op, err := s.Store.RetryNode(r.Context(), Principal(r.Context()), r.PathValue("id"))
		operation(w, op, err)
	}))
	mux.HandleFunc("POST /api/v1/nodes/{id}/recovery-token", s.auth(func(w http.ResponseWriter, r *http.Request) {
		if Principal(r.Context()).TokenID != "" {
			Fail(w, application.ErrForbidden)
			return
		}
		token, err := s.Store.CreateRecoveryToken(r.Context(), Principal(r.Context()), r.PathValue("id"))
		result(w, map[string]any{"token": token, "expires_in": 600}, err)
	}))
	mux.HandleFunc("POST /api/v1/join-tokens", s.auth(func(w http.ResponseWriter, r *http.Request) {
		var v struct {
			Name       string `json:"name"`
			GroupID    string `json:"group_id"`
			MaxUses    int    `json:"max_uses"`
			TTLSeconds int    `json:"ttl_seconds"`
		}
		if !Decode(w, r, &v) {
			return
		}
		if v.MaxUses < 0 || v.MaxUses > 1000000000 || v.TTLSeconds < 60 || v.TTLSeconds > 315360000 {
			JSON(w, 400, map[string]string{"error": "TTL 60–315360000 секунд; использований 0 (без лимита)–1000000000"})
			return
		}
		token, err := s.Store.CreateNamedJoinToken(r.Context(), Principal(r.Context()), v.GroupID, v.Name, v.MaxUses, time.Duration(v.TTLSeconds)*time.Second)
		result(w, map[string]string{"token": token}, err)
	}))
	mux.HandleFunc("GET /api/v1/operations", s.auth(s.collection("operations")))
	mux.HandleFunc("GET /api/v1/operations/{id}/targets", s.auth(func(w http.ResponseWriter, r *http.Request) {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		v, next, err := s.Store.OperationTargetsPage(r.Context(), Principal(r.Context()), r.PathValue("id"), limit, r.URL.Query().Get("after"))
		w.Header().Set("X-Heimdall-Next-Cursor", next)
		result(w, v, err)
	}))
	mux.HandleFunc("GET /api/v1/incidents", s.auth(s.collection("incidents")))
	mux.HandleFunc("POST /api/v1/incidents/{id}/acknowledge", s.auth(func(w http.ResponseWriter, r *http.Request) {
		err := s.Store.Acknowledge(r.Context(), Principal(r.Context()), r.PathValue("id"))
		result(w, map[string]bool{"ok": true}, err)
	}))
	mux.HandleFunc("GET /api/v1/audit", s.auth(s.collection("audit")))
	mux.HandleFunc("GET /api/v1/tokens", s.auth(s.collection("tokens")))
	mux.HandleFunc("POST /api/v1/tokens", s.auth(func(w http.ResponseWriter, r *http.Request) {
		p := Principal(r.Context())
		if p.TokenID != "" {
			Fail(w, application.ErrForbidden)
			return
		}
		var v application.Token
		if !Decode(w, r, &v) {
			return
		}
		token, secret, err := s.Store.CreateToken(r.Context(), p, v)
		result(w, map[string]any{"token": token, "secret": secret}, err)
	}))
	mux.HandleFunc("DELETE /api/v1/tokens/{id}", s.auth(func(w http.ResponseWriter, r *http.Request) {
		p := Principal(r.Context())
		if !p.Self(p.UserID) {
			Fail(w, application.ErrForbidden)
			return
		}
		err := s.Store.RevokeToken(r.Context(), p, r.PathValue("id"))
		result(w, map[string]bool{"ok": true}, err)
	}))
	mux.HandleFunc("POST /api/v1/me/totp/begin", s.auth(s.totpBegin))
	mux.HandleFunc("POST /api/v1/me/totp/finish", s.auth(s.totpFinish))
	mux.HandleFunc("POST /api/v1/me/passkey/begin", s.auth(s.registrationBegin))
	mux.HandleFunc("POST /api/v1/me/passkey/finish", s.auth(s.registrationFinish))
	mux.HandleFunc("PUT /api/v1/me/factor-policy", s.auth(s.personalFactorPolicy))
}
