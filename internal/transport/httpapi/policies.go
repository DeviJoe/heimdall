package httpapi

import (
	"Heimdall/internal/application"
	"Heimdall/internal/authorization"
	"Heimdall/internal/fleet"
	"net/http"
	"strconv"
)

func (s *Server) policyRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/incidents/resolve", s.auth(func(w http.ResponseWriter, r *http.Request) {
		var v struct {
			IDs []string `json:"ids"`
		}
		if !Decode(w, r, &v) {
			return
		}
		err := s.Store.ResolveIncidents(r.Context(), Principal(r.Context()), v.IDs)
		result(w, map[string]bool{"ok": true}, err)
	}))
	mux.HandleFunc("DELETE /api/v1/groups/{id}", s.auth(func(w http.ResponseWriter, r *http.Request) {
		op, err := s.Store.DeleteGroup(r.Context(), Principal(r.Context()), r.PathValue("id"))
		operation(w, op, err)
	}))
	mux.HandleFunc("DELETE /api/v1/user-groups/{id}", s.auth(func(w http.ResponseWriter, r *http.Request) {
		op, err := s.Store.DeleteUserGroup(r.Context(), Principal(r.Context()), r.PathValue("id"))
		operation(w, op, err)
	}))
	mux.HandleFunc("DELETE /api/v1/unix-groups/{id}", s.auth(func(w http.ResponseWriter, r *http.Request) {
		op, err := s.Store.DeleteUnixGroup(r.Context(), Principal(r.Context()), r.PathValue("id"))
		operation(w, op, err)
	}))

	mux.HandleFunc("POST /api/v1/incidents/{id}/resolve", s.auth(func(w http.ResponseWriter, r *http.Request) {
		err := s.Store.ResolveActivityIncident(r.Context(), Principal(r.Context()), r.PathValue("id"))
		result(w, map[string]bool{"ok": true}, err)
	}))
	mux.HandleFunc("GET /api/v1/user-groups/{id}/bindings", s.auth(s.collection("people-bindings")))
	mux.HandleFunc("DELETE /api/v1/user-groups/{id}/bindings/{binding}", s.auth(func(w http.ResponseWriter, r *http.Request) {
		op, err := s.Store.UnbindUserGroupRole(r.Context(), Principal(r.Context()), r.PathValue("id"), r.PathValue("binding"))
		operation(w, op, err)
	}))
	mux.HandleFunc("GET /api/v1/security/events", s.auth(s.collection("security/events")))
	mux.HandleFunc("GET /api/v1/settings", s.auth(func(w http.ResponseWriter, r *http.Request) {
		if !Principal(r.Context()).Allowed("settings.manage", "*") {
			Fail(w, application.ErrForbidden)
			return
		}
		v, err := s.Store.Settings(r.Context())
		result(w, v, err)
	}))
	mux.HandleFunc("PUT /api/v1/settings", s.auth(func(w http.ResponseWriter, r *http.Request) {
		var v application.Settings
		if !Decode(w, r, &v) {
			return
		}
		op, err := s.Store.SaveSettings(r.Context(), Principal(r.Context()), v)
		operation(w, op, err)
	}))
	mux.HandleFunc("GET /api/v1/ansible/inventory", s.auth(func(w http.ResponseWriter, r *http.Request) {
		p := Principal(r.Context())
		allowed := false
		for _, b := range p.Bindings {
			if p.Allowed("inventory.read", b.GroupID) {
				allowed = true
				break
			}
		}
		for _, scope := range p.TokenGroups {
			if p.Allowed("inventory.read", scope) {
				allowed = true
				break
			}
		}
		if p.TokenID == "" || !allowed {
			Fail(w, application.ErrForbidden)
			return
		}
		hosts, err := s.Store.Inventory(r.Context(), p)
		w.Header().Set("Cache-Control", "no-store")
		result(w, application.BuildInventory(hosts), err)
	}))
	mux.HandleFunc("PUT /api/v1/nodes/{id}/ssh", s.auth(func(w http.ResponseWriter, r *http.Request) {
		var v struct {
			Host string `json:"host"`
			Port int    `json:"port"`
		}
		if !Decode(w, r, &v) {
			return
		}
		err := s.Store.SetNodeSSH(r.Context(), Principal(r.Context()), r.PathValue("id"), v.Host, v.Port)
		result(w, map[string]bool{"ok": true}, err)
	}))
	mux.HandleFunc("PUT /api/v1/groups/{id}", s.auth(func(w http.ResponseWriter, r *http.Request) {
		var v fleet.Group
		if !Decode(w, r, &v) {
			return
		}
		v.ID = r.PathValue("id")
		op, err := s.Store.SaveGroup(r.Context(), Principal(r.Context()), v)
		operation(w, op, err)
	}))
	mux.HandleFunc("POST /api/v1/nodes/move", s.auth(func(w http.ResponseWriter, r *http.Request) {
		var v struct {
			NodeIDs []string `json:"node_ids"`
			GroupID string   `json:"group_id"`
		}
		if !Decode(w, r, &v) {
			return
		}
		op, err := s.Store.MoveNodes(r.Context(), Principal(r.Context()), v.NodeIDs, v.GroupID)
		operation(w, op, err)
	}))
	mux.HandleFunc("PUT /api/v1/users/{id}/mfa-policy", s.auth(func(w http.ResponseWriter, r *http.Request) {
		var v struct {
			Policy string `json:"policy"`
		}
		if !Decode(w, r, &v) {
			return
		}
		op, err := s.Store.SetMFAPolicy(r.Context(), Principal(r.Context()), r.PathValue("id"), v.Policy)
		operation(w, op, err)
	}))
	mux.HandleFunc("GET /api/v1/user-groups", s.auth(s.collection("user-groups")))
	mux.HandleFunc("POST /api/v1/user-groups", s.auth(func(w http.ResponseWriter, r *http.Request) {
		var v application.UserGroup
		if !Decode(w, r, &v) {
			return
		}
		op, err := s.Store.SaveUserGroup(r.Context(), Principal(r.Context()), v)
		operation(w, op, err)
	}))
	mux.HandleFunc("POST /api/v1/user-groups/{id}/bindings", s.auth(func(w http.ResponseWriter, r *http.Request) {
		var v authorization.Binding
		if !Decode(w, r, &v) {
			return
		}
		op, err := s.Store.BindUserGroupRole(r.Context(), Principal(r.Context()), r.PathValue("id"), v)
		operation(w, op, err)
	}))
}

func (s *Server) collection(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		status := r.URL.Query().Get("status")
		if r.URL.Query().Get("all") == "true" {
			status = "all"
		}
		parent := r.URL.Query().Get("parent")
		if r.PathValue("id") != "" {
			parent = r.PathValue("id")
		}
		if name == "security/labels" {
			parent = r.URL.Query().Get("resource_id")
			status = r.URL.Query().Get("resource_type")
		}
		v, err := s.Store.ReadPage(r.Context(), Principal(r.Context()), name, application.PageQuery{Limit: limit, After: r.URL.Query().Get("after"), Search: r.URL.Query().Get("query"), Status: status, Parent: parent})
		w.Header().Set("X-Heimdall-Next-Cursor", v.Next)
		result(w, v.Items, err)
	}
}
