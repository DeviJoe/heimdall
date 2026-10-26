package helper

import (
	"Heimdall/internal/platform/security"
	"Heimdall/internal/synchronization"
	"os"
	"path/filepath"
	"testing"
)

func TestRootEnrollmentBinding(t *testing.T) {
	dir := t.TempDir()
	if _, err := loadBootstrap(dir, "", false); err == nil {
		t.Fatal("unbound initial helper allowed")
	}
	pin, err := loadBootstrap(dir, "operator-join-token", false)
	if err != nil {
		t.Fatal(err)
	}
	again, err := loadBootstrap(dir, "different-token", false)
	if err != nil || again != pin {
		t.Fatal("root intent was replaced", err)
	}
	state := synchronization.Snapshot{BootstrapNonce: pin.Nonce, BootstrapTokenHash: pin.TokenHash}
	if err = pin.verify(state, false); err != nil {
		t.Fatal(err)
	}
	state.BootstrapNonce = security.HashToken("another-host")
	if pin.verify(state, false) == nil {
		t.Fatal("another host's initial manifest accepted")
	}
	state.BootstrapNonce = pin.Nonce
	state.BootstrapTokenHash = security.HashToken("different-join-token")
	if pin.verify(state, false) == nil {
		t.Fatal("different enrollment intent accepted")
	}
	if pin.verify(state, true) != nil {
		t.Fatal("established node must use its root node ID checkpoint")
	}
	if err = os.Chmod(filepath.Join(dir, "bootstrap.json"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = loadBootstrap(dir, "operator-join-token", false); err == nil {
		t.Fatal("unsafe bootstrap journal accepted")
	}
}
func TestBootstrapJournalRejectsSymlinkAndPreservesExistingNodes(t *testing.T) {
	dir := t.TempDir()
	if pin, err := loadBootstrap(dir, "", true); err != nil || pin.Nonce != "" {
		t.Fatal("existing checkpoint migration failed", err)
	}
	other := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(other, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, filepath.Join(dir, "bootstrap.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := loadBootstrap(dir, "token", false); err == nil {
		t.Fatal("symlink accepted")
	}
}
