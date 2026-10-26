package httpapi

import (
	"Heimdall/internal/application"
	"Heimdall/internal/authorization"
	"Heimdall/internal/fleet"
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type fakeCatalog struct {
	application.ControlPlane
	disabled bool
}

func (f *fakeCatalog) Settings(context.Context) (application.Settings, error) {
	return application.Settings{OfflineSeconds: 45, MCPEnabled: true, SwaggerEnabled: true}, nil
}
func (f *fakeCatalog) Bearer(ctx context.Context, secret, audience string) (authorization.Principal, error) {
	if secret != "mcp-read" || audience != "mcp" {
		return authorization.Principal{}, application.ErrForbidden
	}
	p := authorization.Principal{UserID: "caller", TokenID: "token", TokenScopes: []string{"nodes.read"}, Bindings: []authorization.Binding{{GroupID: "*", Role: authorization.Role{Permissions: []string{"*"}}}}}
	p.Prepare()
	return p, nil
}
func (f *fakeCatalog) NodesPage(ctx context.Context, p authorization.Principal, offline time.Duration, limit int, after string) ([]fleet.Node, string, error) {
	if !p.Allowed("nodes.read", "*") {
		return nil, "", application.ErrForbidden
	}
	return []fleet.Node{{ID: "visible"}}, "next", nil
}
func (f *fakeCatalog) QueryNodesPage(ctx context.Context, p authorization.Principal, offline time.Duration, limit int, after, group, search string) ([]fleet.Node, string, error) {
	return f.NodesPage(ctx, p, offline, limit, after)
}
func (f *fakeCatalog) SetUserStatus(ctx context.Context, p authorization.Principal, id, status string) (string, error) {
	if !p.Allowed("users.manage", "*") {
		return "", application.ErrForbidden
	}
	f.disabled = true
	return "op", nil
}
func TestMCPChecksAudienceOriginAndToolPermissions(t *testing.T) {
	repository := &fakeCatalog{}
	s := &Server{Store: repository}
	s.Config.Server.PublicURL = "https://linpam.test"
	call := func(token, cookie, origin, body string) (int, map[string]any) {
		r := httptest.NewRequest("POST", "https://linpam.test/mcp", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		r.Header.Set("MCP-Protocol-Version", "2025-11-25")
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: "linpam_session", Value: cookie})
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		s.mcpHandler().ServeHTTP(w, r)
		var out map[string]any
		json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	payload := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_nodes","arguments":{}}}`
	for _, test := range []struct {
		token, cookie, origin string
		code                  int
	}{{"", "session", "", 401}, {"join-token", "", "", 401}, {"mcp-read", "", "https://evil.test", 403}, {"mcp-read", "", "", 200}} {
		code, out := call(test.token, test.cookie, test.origin, payload)
		if code != test.code {
			t.Fatalf("HTTP %d want %d: %+v", code, test.code, out)
		}
		if code == 200 {
			raw, _ := json.Marshal(out)
			if !bytes.Contains(raw, []byte("visible")) {
				t.Fatalf("tool data missing: %s", raw)
			}
		}
	}
	_, out := call("mcp-read", "", "", `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"disable_user","arguments":{"user_id":"other"}}}`)
	if repository.disabled {
		t.Fatal("read token executed mutation")
	}
	raw, _ := json.Marshal(out)
	if !bytes.Contains(raw, []byte(`"isError":true`)) {
		t.Fatalf("permission failure missing: %s", raw)
	}
}
func TestDecodeRejectsTrailingMalformedJSON(t *testing.T) {
	for _, body := range []string{`{} garbage`, `{} {}`, `{"unknown":1}`} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("POST", "/", strings.NewReader(body))
		if Decode(w, r, &struct{}{}) {
			t.Fatalf("accepted %q", body)
		}
	}
}

func TestConfigurationCanKeepOptionalEndpointsDisabled(t *testing.T) {
	s := &Server{Store: &fakeCatalog{}}
	for _, path := range []string{"/swagger", "/api/v1/openapi.json", "/mcp"} {
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Code != 404 {
			t.Fatalf("disabled endpoint %s returned %d", path, w.Code)
		}
	}
}
