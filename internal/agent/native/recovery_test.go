package native

import (
	"Heimdall/internal/identity"
	"Heimdall/internal/synchronization"
	"testing"
)

func cacheAccount(id, login string, uid int, group string) synchronization.Account {
	return synchronization.Account{User: identity.User{ID: id, Login: login, UID: uid, GID: uid, Home: "/home/" + login, Shell: "/bin/sh"}, Enabled: true, Groups: []string{group}}
}

func TestDesiredDeltaRetainsOtherUsersUnixGroups(t *testing.T) {
	old := synchronization.Snapshot{Schema: 2, Full: true, NodeID: "node", Epoch: "epoch", Revision: 10,
		Accounts: []synchronization.Account{cacheAccount("alice", "alice", 10001, "engineering"), cacheAccount("bob", "bob", 10002, "operations")},
		Groups:   []synchronization.UnixGroup{{ID: "eng", Name: "engineering", GID: 11001}, {ID: "ops", Name: "operations", GID: 11002}}}
	delta := synchronization.Snapshot{Schema: 2, NodeID: "node", Epoch: "epoch", Revision: 11, BaseRevision: 10,
		Accounts: []synchronization.Account{old.Accounts[0]}, Groups: []synchronization.UnixGroup{old.Groups[0]}}
	delta.Accounts[0].User.GECOS = "Updated Alice"
	merged, err := materializeDesired(old, delta)
	if err != nil {
		t.Fatal(err)
	}
	if !merged.Full || merged.BaseRevision != 0 || merged.Revision != 11 || len(merged.Accounts) != 2 || len(merged.Groups) != 2 {
		t.Fatalf("incomplete offline manifest: accounts=%d groups=%d", len(merged.Accounts), len(merged.Groups))
	}
	if merged.Accounts[0].User.GECOS != "Updated Alice" || merged.Accounts[1].Groups[0] != "operations" {
		t.Fatal("delta lost the update or unchanged membership")
	}
	// Revocation of Alice must not remove Bob's group from the replay manifest.
	delta.Revision = 12
	delta.BaseRevision = 11
	delta.Accounts[0].Enabled = false
	delta.Accounts[0].Groups = nil
	delta.Groups = nil
	revoked, err := materializeDesired(merged, delta)
	if err != nil || revoked.Accounts[0].Enabled || len(revoked.Accounts[1].Groups) != 1 {
		t.Fatalf("invalid revocation cache: %v", err)
	}
	// A full manifest is authoritative and does not retain unused definitions.
	full := revoked
	full.Groups = []synchronization.UnixGroup{old.Groups[1]}
	replaced, err := materializeDesired(old, full)
	if err != nil || len(replaced.Groups) != 1 {
		t.Fatalf("full manifest did not replace group definitions: %v", err)
	}
}

func TestDesiredDeltaRejectsGroupIdentityReplacement(t *testing.T) {
	old := synchronization.Snapshot{Schema: 2, Full: true, NodeID: "node", Epoch: "epoch", Revision: 1, Groups: []synchronization.UnixGroup{{ID: "ops", Name: "operations", GID: 11002}}}
	delta := old
	delta.Full = false
	delta.Revision = 2
	delta.Groups = []synchronization.UnixGroup{{ID: "other", Name: "operations", GID: 11003}}
	if _, err := materializeDesired(old, delta); err == nil {
		t.Fatal("delta replaced an existing UNIX group identity")
	}
}
