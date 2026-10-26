package launcher

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func cleanEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{"HEIMDALL_AGENT_CONFIG", "HEIMDALL_AGENT_NAME", "HEIMDALL_NODE_NAME", "HEIMDALL_AGENT_HEARTBEAT", "HEIMDALL_JOIN_TOKEN"} {
		t.Setenv(key, "")
		if err := os.Unsetenv(key); err != nil {
			t.Fatal(err)
		}
	}
}
func TestConfigPrecedence(t *testing.T) {
	cleanEnv(t)
	path := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(path, []byte("name: from-yaml\nheartbeat: 20s\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HEIMDALL_AGENT_NAME", "from-env")
	t.Setenv("HEIMDALL_AGENT_HEARTBEAT", "30s")
	t.Setenv("HEIMDALL_JOIN_TOKEN", "test-token")
	c, err := Parse([]string{"--config", path, "--name", "from-cli"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Name != "from-cli" || c.Heartbeat != 30*time.Second || c.JoinToken != "test-token" {
		t.Fatal("YAML/ENV/CLI precedence lost")
	}
}
func TestSecretYAMLRequiresPrivateMode(t *testing.T) {
	cleanEnv(t)
	path := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(path, []byte("join_token: test-token\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Parse([]string{"-config", path}); err == nil {
		t.Fatal("world-readable token accepted")
	}
}
func TestUnknownYAMLAndUnsafePathsAreRejected(t *testing.T) {
	cleanEnv(t)
	path := filepath.Join(t.TempDir(), "agent.yaml")
	for _, raw := range []string{"unknown: true\n", "name: node\n---\nname: other\n", "state_dir: relative\n", "state_dir: /same\nworker_state_dir: /same\n"} {
		if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Parse([]string{"-config", path}); err == nil {
			t.Fatalf("unsafe YAML accepted: %s", raw)
		}
	}
}
