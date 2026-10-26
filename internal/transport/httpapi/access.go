package httpapi

import (
	"Heimdall/internal/application"
	"net/http"
	"strconv"
)

func (s *Server) accessGraph(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	graph, next, err := s.Store.AccessGraph(r.Context(), Principal(r.Context()), application.PageQuery{Limit: limit, After: r.URL.Query().Get("after"), Search: r.URL.Query().Get("query"), Status: r.URL.Query().Get("kind")})
	w.Header().Set("X-Heimdall-Next-Cursor", next)
	result(w, graph, err)
}

func (s *Server) accessibleNodes(w http.ResponseWriter, r *http.Request) {
	p := Principal(r.Context())
	if p.Restricted || p.TokenID != "" {
		Fail(w, application.ErrForbidden)
		return
	}
	userID := r.PathValue("id")
	if userID == "" {
		userID = p.UserID
	}
	if userID != p.UserID && !p.Allowed("users.manage", "*") {
		Fail(w, application.ErrForbidden)
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	nodes, next, err := s.Store.AccessibleNodesPage(r.Context(), p, userID, limit, r.URL.Query().Get("after"), r.URL.Query().Get("query"))
	w.Header().Set("X-Heimdall-Next-Cursor", next)
	result(w, nodes, err)
}

func (s *Server) nativeAccessPolicy(w http.ResponseWriter, r *http.Request) {
	p := Principal(r.Context())
	id := r.PathValue("id")
	if id == "" {
		id = p.UserID
	}
	v, err := s.Store.NativeAccessPolicy(r.Context(), p, id)
	result(w, v, err)
}
