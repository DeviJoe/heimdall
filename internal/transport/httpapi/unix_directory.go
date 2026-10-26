package httpapi

import (
	"Heimdall/internal/application"
	"errors"
	"net/http"
	"strconv"
	"time"
)

func (s *Server) unixRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/unix-groups/{id}", s.auth(func(w http.ResponseWriter, r *http.Request) {
		v, err := s.Store.ReadPage(r.Context(), Principal(r.Context()), "unix-groups", application.PageQuery{Limit: 1, Parent: r.PathValue("id")})
		if err != nil {
			Fail(w, err)
			return
		}
		if len(v.Items) == 0 {
			Fail(w, application.ErrNotFound)
			return
		}
		JSON(w, 200, v.Items[0])
	}))
	mux.HandleFunc("POST /api/v1/unix-groups/{id}/members", s.auth(func(w http.ResponseWriter, r *http.Request) {
		var v struct{ Add, Remove []string }
		if !Decode(w, r, &v) {
			return
		}
		op, err := s.Store.UpdateUnixMembers(r.Context(), Principal(r.Context()), r.PathValue("id"), v.Add, v.Remove)
		operation(w, op, err)
	}))

	mux.HandleFunc("PUT /api/v1/join-tokens/{id}", s.auth(func(w http.ResponseWriter, r *http.Request) {
		var v struct {
			MaxUses int       `json:"max_uses"`
			Expires time.Time `json:"expires_at"`
		}
		if !Decode(w, r, &v) {
			return
		}
		err := s.Store.UpdateJoinToken(r.Context(), Principal(r.Context()), r.PathValue("id"), v.MaxUses, v.Expires)
		result(w, map[string]bool{"ok": true}, err)
	}))

	mux.HandleFunc("POST /api/v1/user-groups/{id}/members/remove", s.auth(func(w http.ResponseWriter, r *http.Request) {
		var v struct {
			Users []string `json:"users"`
		}
		if !Decode(w, r, &v) {
			return
		}
		op, err := s.Store.RemovePeople(r.Context(), Principal(r.Context()), r.PathValue("id"), v.Users)
		operation(w, op, err)
	}))

	mux.HandleFunc("DELETE /api/v1/roles/{id}", s.auth(func(w http.ResponseWriter, r *http.Request) {
		op, err := s.Store.DeleteRole(r.Context(), Principal(r.Context()), r.PathValue("id"))
		operation(w, op, err)
	}))
	mux.HandleFunc("POST /api/v1/user-groups/move", s.auth(func(w http.ResponseWriter, r *http.Request) {
		var v struct {
			Source string   `json:"source"`
			Target string   `json:"target"`
			Users  []string `json:"users"`
		}
		if !Decode(w, r, &v) {
			return
		}
		op, err := s.Store.MovePeople(r.Context(), Principal(r.Context()), v.Source, v.Target, v.Users)
		operation(w, op, err)
	}))
	mux.HandleFunc("GET /api/v1/users/{id}/factors", s.auth(func(w http.ResponseWriter, r *http.Request) {
		p := Principal(r.Context())
		id := r.PathValue("id")
		keys, err := s.Store.Passkeys(r.Context(), p, id)
		if err != nil {
			Fail(w, err)
			return
		}
		state, err := s.Store.FactorState(r.Context(), id)
		administratorReset := p.UserID != id && p.Allowed("users.manage", "*")
		result(w, map[string]any{
			"passkeys": keys, "totp_enabled": state.TOTP, "required": state.Required,
			"administrator_required": state.AdministratorRequired, "personal_policy": state.PersonalPolicy,
			"can_remove_totp":    administratorReset || state.Satisfied(false, state.Passkey),
			"can_remove_passkey": administratorReset || state.Satisfied(state.TOTP, len(keys) > 1),
		}, err)
	}))
	mux.HandleFunc("PUT /api/v1/users/{id}/passkeys/{key}", s.auth(func(w http.ResponseWriter, r *http.Request) {
		var v struct {
			Name string `json:"name"`
		}
		if !Decode(w, r, &v) {
			return
		}
		err := s.Store.RenamePasskey(r.Context(), Principal(r.Context()), r.PathValue("id"), r.PathValue("key"), v.Name)
		result(w, map[string]bool{"ok": true}, err)
	}))
	mux.HandleFunc("DELETE /api/v1/users/{id}/passkeys/{key}", s.auth(s.removeFactor))
	mux.HandleFunc("DELETE /api/v1/users/{id}/totp", s.auth(s.removeFactor))
	mux.HandleFunc("GET /api/v1/security/labels", s.auth(s.collection("security/labels")))
	mux.HandleFunc("POST /api/v1/security/labels", s.auth(func(w http.ResponseWriter, r *http.Request) {
		var v application.LabelPolicy
		if !Decode(w, r, &v) {
			return
		}
		op, err := s.Store.SaveLabelPolicy(r.Context(), Principal(r.Context()), v)
		operation(w, op, err)
	}))
	mux.HandleFunc("GET /api/v1/announcements", s.auth(s.collection("announcements")))
	mux.HandleFunc("POST /api/v1/announcements", s.auth(func(w http.ResponseWriter, r *http.Request) {
		var v application.Announcement
		if !Decode(w, r, &v) {
			return
		}
		op, err := s.Store.SaveAnnouncement(r.Context(), Principal(r.Context()), v)
		operation(w, op, err)
	}))
	mux.HandleFunc("DELETE /api/v1/announcements/{id}", s.auth(s.deleteAnnouncement))
	mux.HandleFunc("GET /api/v1/unix-groups", s.auth(s.collection("unix-groups")))
	mux.HandleFunc("POST /api/v1/unix-groups", s.auth(func(w http.ResponseWriter, r *http.Request) {
		var v application.UnixGroup
		if !Decode(w, r, &v) {
			return
		}
		op, err := s.Store.SaveUnixGroup(r.Context(), Principal(r.Context()), v)
		operation(w, op, err)
	}))
	mux.HandleFunc("GET /api/v1/unix-assignments", s.auth(s.collection("unix-assignments")))
	mux.HandleFunc("POST /api/v1/unix-assignments", s.auth(func(w http.ResponseWriter, r *http.Request) {
		var v application.UnixAssignment
		if !Decode(w, r, &v) {
			return
		}
		op, err := s.Store.AssignUnixGroup(r.Context(), Principal(r.Context()), v)
		operation(w, op, err)
	}))
	mux.HandleFunc("DELETE /api/v1/unix-assignments/{id}", s.auth(func(w http.ResponseWriter, r *http.Request) {
		op, err := s.Store.UnassignUnixGroup(r.Context(), Principal(r.Context()), r.PathValue("id"))
		operation(w, op, err)
	}))
	mux.HandleFunc("GET /api/v1/join-tokens", s.auth(s.collection("join-tokens")))
	mux.HandleFunc("DELETE /api/v1/join-tokens/{id}", s.auth(func(w http.ResponseWriter, r *http.Request) {
		err := s.Store.RevokeJoinToken(r.Context(), Principal(r.Context()), r.PathValue("id"))
		result(w, map[string]bool{"ok": true}, err)
	}))
}

func (s *Server) deleteAnnouncement(w http.ResponseWriter, r *http.Request) {
	version, err := strconv.ParseInt(r.URL.Query().Get("version"), 10, 64)
	if err != nil || version < 1 {
		JSON(w, http.StatusBadRequest, map[string]string{"error": "Укажите версию сообщения"})
		return
	}
	op, err := s.Store.DeleteAnnouncement(r.Context(), Principal(r.Context()), r.PathValue("id"), version)
	if errors.Is(err, application.ErrConflict) {
		JSON(w, http.StatusConflict, map[string]string{"error": "Сообщение уже изменено. Откройте его актуальную версию перед удалением."})
		return
	}
	operation(w, op, err)
}

func (s *Server) removeFactor(w http.ResponseWriter, r *http.Request) {
	p := Principal(r.Context())
	id := r.PathValue("id")
	key := r.PathValue("key")
	if key == "" {
		key = "totp"
	}
	op, err := s.Store.RemoveFactor(r.Context(), p, id, key)
	if err == nil && p.UserID == id && p.TokenID == "" {
		err = s.newSession(w, r, id)
	}
	operation(w, op, err)
}
