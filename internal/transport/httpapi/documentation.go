package httpapi

import (
	"Heimdall/internal/application"
	"Heimdall/internal/knowledge"
	"errors"
	"net/http"
	"strconv"
)

func (s *Server) documentationList(w http.ResponseWriter, r *http.Request) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	v, next, err := s.Store.DocumentationPages(r.Context(), Principal(r.Context()), limit, r.URL.Query().Get("after"), r.URL.Query().Get("query"))
	w.Header().Set("X-Heimdall-Next-Cursor", next)
	result(w, v, err)
}
func (s *Server) documentationRead(w http.ResponseWriter, r *http.Request) {
	v, err := s.Store.DocumentationPage(r.Context(), Principal(r.Context()), r.PathValue("slug"))
	result(w, v, err)
}
func (s *Server) documentationSave(w http.ResponseWriter, r *http.Request) {
	var v knowledge.Page
	if !Decode(w, r, &v) {
		return
	}
	v.Slug = r.PathValue("slug")
	op, err := s.Store.SaveDocumentation(r.Context(), Principal(r.Context()), v)
	if errors.Is(err, application.ErrConflict) {
		JSON(w, 409, map[string]string{"error": "Статья уже изменена. Откройте актуальную версию; ваш текст сохранён в редакторе."})
		return
	}
	operation(w, op, err)
}
