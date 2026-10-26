package gateway

import (
	"Heimdall/internal/synchronization"
	"testing"
)

func TestFencingDoesNotCancelConnectionsCreatedDuringDatabaseRead(t *testing.T) {
	cancelled := map[string]bool{}
	conn := func(id string, generation int64) *connection {
		return &connection{generation: generation, serial: id, cancel: func() { cancelled[id] = true }}
	}
	old := conn("old", 1)
	replacement := conn("replacement", 2)
	newNode := conn("new", 1)
	stale := conn("stale", 1)
	g := &Gateway{connections: map[string]*connection{"a": replacement, "b": newNode, "c": stale}}
	g.fence(map[string]*connection{"a": old, "c": stale}, map[string]synchronization.ConnectionIdentity{"a": {Generation: 1, Serial: "old"}, "c": {Generation: 2, Serial: "stale"}})
	if cancelled["replacement"] || cancelled["new"] || cancelled["old"] {
		t.Fatal("a connection outside the captured generation was cancelled")
	}
	if !cancelled["stale"] {
		t.Fatal("stale captured generation was not cancelled")
	}
}
