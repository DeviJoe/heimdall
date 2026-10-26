package native

import (
	"Heimdall/internal/authorization"
	"Heimdall/internal/identity"
	"Heimdall/internal/synchronization"
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicWriteRejectsSymlinks(t *testing.T) {
	dir := t.TempDir()
	original := filepath.Join(dir, "original")
	if err := os.WriteFile(original, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(original, link); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWrite(link, []byte("overwrite"), 0644); err == nil {
		t.Fatal("followed target symlink")
	}
	parent := filepath.Join(dir, "parent")
	if err := os.Symlink(dir, parent); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWrite(filepath.Join(parent, "child"), []byte("overwrite"), 0644); err == nil {
		t.Fatal("followed parent symlink")
	}
	data, _ := os.ReadFile(original)
	if string(data) != "original" {
		t.Fatal("original overwritten")
	}
}
func TestDisabledManifestAndSudoText(t *testing.T) {
	u := identity.User{ID: "u", Login: "alice", UID: 10001, GID: 10001, Home: "/home/alice", Shell: "/bin/bash"}
	state := synchronization.Snapshot{Schema: 1, Full: true, NodeID: "node", Epoch: "epoch", Revision: 1, Accounts: []synchronization.Account{{User: u, Enabled: false, PasswordHash: "$6$bad"}}}
	if Validate(state) == nil {
		t.Fatal("disabled user retained credentials")
	}
	a := synchronization.Account{User: u, Enabled: true, Sudo: []authorization.SudoRule{{Command: "/usr/bin/id", RunAs: "root", NoPassword: true}}}
	if got := SudoFile(a); got != "alice ALL=(root) NOPASSWD: /usr/bin/id \"\"\n" {
		t.Fatalf("sudo syntax changed: %q", got)
	}
}
