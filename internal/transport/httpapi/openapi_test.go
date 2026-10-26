package httpapi

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
)

func TestOpenAPIDescribesRegisteredRoutesAndModels(t *testing.T) {
	doc := openAPI()
	if _, err := json.Marshal(doc); err != nil {
		t.Fatal(err)
	}
	paths := doc["paths"].(specObject)
	models := doc["components"].(specObject)["schemas"].(specObject)
	seen := map[string]bool{}
	for _, op := range openAPIOperations() {
		operation := paths[op.Path].(specObject)[op.Method].(specObject)
		id := operation["operationId"].(string)
		if seen[id] {
			t.Fatalf("duplicate operationId %s", id)
		}
		seen[id] = true
		if op.Input != "" && models[op.Input] == nil {
			t.Fatalf("missing input %s", op.Input)
		}
		if op.Output != "SSE" && op.Output != "Redirect" && models[strings.TrimPrefix(op.Output, "[]")] == nil {
			t.Fatalf("missing output %s", op.Output)
		}
		if operation["x-heimdall-authorization"] == "" {
			t.Fatal("missing authorization")
		}
	}
	route := regexp.MustCompile(`HandleFunc\("(GET|POST|PUT|DELETE) ([^\"]+)"`)
	for _, file := range []string{"server.go", "resources.go", "policies.go", "unix_directory.go", "integrations.go", "openapi.go"} {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range route.FindAllStringSubmatch(string(data), -1) {
			if match[2] == "/swagger" {
				continue
			}
			item, ok := paths[match[2]].(specObject)
			if !ok || item[strings.ToLower(match[1])] == nil {
				t.Fatalf("undocumented %s %s", match[1], match[2])
			}
		}
	}
	var visit func(any)
	visit = func(v any) {
		switch x := v.(type) {
		case specObject:
			if r, ok := x["$ref"].(string); ok {
				if !strings.HasPrefix(r, "#/components/schemas/") || models[strings.TrimPrefix(r, "#/components/schemas/")] == nil {
					t.Fatalf("unresolved ref %s", r)
				}
			}
			for _, v := range x {
				visit(v)
			}
		case []any:
			for _, v := range x {
				visit(v)
			}
		}
	}
	visit(doc)
}
func TestOpenAPISecurityAndPagination(t *testing.T) {
	paths := openAPI()["paths"].(specObject)
	for path, auth := range map[string]string{"/api/v1/auth/providers": "", "/api/v1/me/totp/begin": "cookieAuth", "/api/v1/tokens": "cookieAuth", "/api/v1/ansible/inventory": "bearerAuth"} {
		method := "get"
		if path == "/api/v1/me/totp/begin" || path == "/api/v1/tokens" {
			method = "post"
		}
		sec := paths[path].(specObject)[method].(specObject)["security"].([]any)
		if auth == "" {
			if len(sec) != 0 {
				t.Fatal("public endpoint requires session")
			}
		} else if len(sec) != 1 || sec[0].(specObject)[auth] == nil {
			t.Fatalf("wrong security %s", path)
		}
	}
	for _, op := range openAPIOperations() {
		if op.Page {
			response := paths[op.Path].(specObject)[op.Method].(specObject)["responses"].(specObject)["200"].(specObject)
			if response["headers"].(specObject)["X-Heimdall-Next-Cursor"] == nil {
				t.Fatalf("missing cursor %s", op.Path)
			}
		}
	}
}
