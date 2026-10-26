package httpapi

import (
	"Heimdall/internal/application"
	"Heimdall/internal/authorization"
	"context"
	"net/http/httptest"
	"strings"
	"testing"
)

type inventoryCatalog struct {
	application.ControlPlane
	read bool
}

func (f *inventoryCatalog) Bearer(_ context.Context, secret, audience string) (authorization.Principal, error) {
	if audience != "api" || (secret != "inventory" && secret != "read-only") {
		return authorization.Principal{}, application.ErrForbidden
	}
	scopes := []string{"inventory.read"}
	if secret == "read-only" {
		scopes = []string{"nodes.read"}
	}
	p := authorization.Principal{UserID: "caller", TokenID: "token", TokenScopes: scopes, TokenGroups: []string{"group"}, Bindings: []authorization.Binding{{GroupID: "*", Role: authorization.Role{Permissions: []string{"*"}}}}}
	p.Prepare()
	return p, nil
}
func (f *inventoryCatalog) Inventory(_ context.Context, p authorization.Principal) ([]application.InventoryHost, error) {
	f.read = true
	if !p.Allowed("inventory.read", "group") {
		return nil, application.ErrForbidden
	}
	return []application.InventoryHost{{ID: "visible", GroupID: "group", Host: "host.internal", Port: 22, Login: "caller"}}, nil
}
func TestInventoryTokenScopeAndGlobalRoleIntersection(t *testing.T) {
	catalog := &inventoryCatalog{}
	s := &Server{Store: catalog}
	handler := s.Handler()
	for _, test := range []struct {
		token  string
		status int
	}{{"", 401}, {"read-only", 403}, {"inventory", 200}} {
		catalog.read = false
		request := httptest.NewRequest("GET", "/api/v1/ansible/inventory", nil)
		if test.token != "" {
			request.Header.Set("Authorization", "Bearer "+test.token)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != test.status {
			t.Fatalf("token %q: HTTP %d %s", test.token, response.Code, response.Body.String())
		}
		if test.status != 200 && catalog.read {
			t.Fatal("unauthorized request reached inventory adapter")
		}
		if test.status == 200 && !strings.Contains(response.Body.String(), "host.internal") {
			t.Fatal("missing hostvars")
		}
	}
}
