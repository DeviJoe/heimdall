package httpapi

import (
	"Heimdall/internal/application"
	"Heimdall/internal/authorization"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

type announcementDeleteStore struct {
	application.ControlPlane
	id, actor string
	version   int64
	calls     int
	err       error
}

func (s *announcementDeleteStore) DeleteAnnouncement(_ context.Context, p authorization.Principal, id string, version int64) (string, error) {
	s.calls++
	s.id, s.actor, s.version = id, p.UserID, version
	return "delete-operation", s.err
}

func TestDeleteAnnouncementValidatesVersionAndPreservesStoreErrors(t *testing.T) {
	for _, tc := range []struct {
		name, query   string
		err           error
		status, calls int
	}{
		{"missing version", "", nil, http.StatusBadRequest, 0},
		{"invalid version", "?version=no", nil, http.StatusBadRequest, 0},
		{"nonpositive version", "?version=0", nil, http.StatusBadRequest, 0},
		{"delete", "?version=2", nil, http.StatusOK, 1},
		{"permission denied", "?version=2", application.ErrForbidden, http.StatusForbidden, 1},
		{"stale message", "?version=2", application.ErrConflict, http.StatusConflict, 1},
		{"missing message", "?version=2", application.ErrNotFound, http.StatusNotFound, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &announcementDeleteStore{err: tc.err}
			server := &Server{Store: store}
			r := httptest.NewRequest("DELETE", "/api/v1/announcements/message"+tc.query, nil)
			r.SetPathValue("id", "message")
			r = r.WithContext(context.WithValue(r.Context(), contextKey{}, authorization.Principal{UserID: "admin"}))
			w := httptest.NewRecorder()
			server.deleteAnnouncement(w, r)
			if w.Code != tc.status || store.calls != tc.calls {
				t.Fatalf("HTTP %d, calls %d: %s", w.Code, store.calls, w.Body.String())
			}
			if tc.calls > 0 && (store.id != "message" || store.actor != "admin" || store.version != 2) {
				t.Fatal("wrong deletion target, identity or version")
			}
		})
	}
}
