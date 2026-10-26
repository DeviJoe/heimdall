package httpapi

import (
	"Heimdall/internal/application"
	"Heimdall/internal/authorization"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type nativeAccessStore struct {
	application.ControlPlane
	caller       string
	limit        int
	after, query string
	calls        int
}

func (s *nativeAccessStore) AccessibleNodesPage(_ context.Context, p authorization.Principal, userID string, limit int, after, query string) ([]application.AccessibleNode, string, error) {
	s.caller, s.limit, s.after, s.query = userID, limit, after, query
	s.calls++
	return []application.AccessibleNode{{ID: "visible", Name: "linux-web", Login: "engineer", Roles: []application.AccessRole{}}}, "next-node", nil
}
func TestAccessibleNodesIsBrowserSelfService(t *testing.T) {
	for _, tc := range []struct {
		name      string
		principal authorization.Principal
		status    int
	}{
		{"native user without management permissions", authorization.Principal{UserID: "engineer"}, 200},
		{"restricted enrollment", authorization.Principal{UserID: "engineer", Restricted: true}, 403},
		{"API token even with global scopes", authorization.Principal{UserID: "engineer", TokenID: "token", TokenScopes: []string{"*"}}, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := &nativeAccessStore{}
			s := &Server{Store: store}
			r := httptest.NewRequest("GET", "/api/v1/me/nodes?limit=20&after=cursor&query=web", nil)
			r = r.WithContext(context.WithValue(r.Context(), contextKey{}, tc.principal))
			w := httptest.NewRecorder()
			s.accessibleNodes(w, r)
			if w.Code != tc.status {
				t.Fatalf("HTTP %d: %s", w.Code, w.Body.String())
			}
			if tc.status == http.StatusOK {
				if store.caller != "engineer" || store.limit != 20 || store.after != "cursor" || store.query != "web" || w.Header().Get("X-Heimdall-Next-Cursor") != "next-node" {
					t.Fatal("self identity or pagination lost")
				}
				if !strings.Contains(w.Body.String(), "linux-web") || strings.Contains(w.Body.String(), "desired_revision") {
					t.Fatal("incorrect portal projection")
				}
			} else if store.calls != 0 {
				t.Fatal("rejected caller reached native directory")
			}
		})
	}
}
