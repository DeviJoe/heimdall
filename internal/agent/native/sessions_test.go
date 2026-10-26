package native

import (
	"Heimdall/internal/identity"
	"testing"
)

func TestRevocationTargetsIncludeUserAndSudoButProtectListener(t *testing.T) {
	idx := indexProcesses([]nativeProcess{
		{PID: 1, UIDs: []int{0}, Start: "init"},
		{PID: 10, Parent: 1, UIDs: []int{0}, Start: "listener", Executable: "sshd", Command: "sshd: /usr/sbin/sshd -D [listener]"},
		{PID: 11, Parent: 10, UIDs: []int{0}, Start: "monitor", Executable: "sshd", Command: "sshd: alice [priv]"},
		{PID: 12, Parent: 11, UIDs: []int{10001}, Start: "user"},
		{PID: 13, Parent: 12, UIDs: []int{0}, Start: "sudo"},
		{PID: 14, Parent: 13, UIDs: []int{0}, Start: "root-shell"},
		{PID: 15, Parent: 1, UIDs: []int{10001}, Start: "nohup"},
		{PID: 16, Parent: 1, UIDs: []int{10002}, Start: "other"},
		{PID: 17, Parent: 1, UIDs: []int{10002}, Start: "forged", Executable: "sshd", Command: "sshd: alice [priv]"},
		{PID: 18, Parent: 1, UIDs: []int{10001}, Start: "zombie", Zombie: true},
	})
	targets := idx.targets(identity.User{UID: 10001, Login: "alice"}, nil)
	want := map[int]bool{11: true, 12: true, 13: true, 14: true, 15: true}
	if len(targets) != len(want) {
		t.Fatalf("unexpected targets: %+v", targets)
	}
	for _, p := range targets {
		if !want[p.PID] {
			t.Fatalf("unrelated process targeted: %+v", p)
		}
	}
}
func TestRevocationJournalRetainsOrphanButRejectsReusedPID(t *testing.T) {
	idx := indexProcesses([]nativeProcess{{PID: 22, Parent: 1, UIDs: []int{0}, Start: "old"}, {PID: 23, Parent: 1, UIDs: []int{0}, Start: "new"}, {PID: 24, Parent: 22, UIDs: []int{0}, Start: "child"}})
	targets := idx.targets(identity.User{UID: 10001, Login: "alice"}, []processTarget{{22, "old"}, {23, "old"}})
	if len(targets) != 2 || targets[0].PID != 22 || targets[1].PID != 24 {
		t.Fatalf("PID identity was lost: %+v", targets)
	}
}
func TestRevocationIncludesSavedUIDAndAuditLoginUID(t *testing.T) {
	idx := indexProcesses([]nativeProcess{{PID: 100, UIDs: []int{0, 0, 10001}, Start: "saved"}, {PID: 101, UIDs: []int{0, 0, 0, 0, 10001}, Start: "audit"}})
	if len(idx.targets(identity.User{UID: 10001}, nil)) != 2 {
		t.Fatal("sudo attribution missing")
	}
}
