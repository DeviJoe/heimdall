package client

import (
	"fmt"
	"testing"
	"time"
)

func TestRenewalDeadlineIsStableAndSpreadsTheFleetBeforeExpiry(t *testing.T) {
	expires := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	deadlines := map[time.Time]bool{}
	for i := range 100 {
		id := fmt.Sprintf("node-%d", i)
		deadline := renewalDeadline(expires, id)
		if deadline.Before(expires.Add(-8*time.Hour)) || !deadline.Before(expires.Add(-7*time.Hour)) {
			t.Fatal("renewal outside the safe window")
		}
		if deadline != renewalDeadline(expires, id) {
			t.Fatal("deadline changes on reconnect")
		}
		deadlines[deadline] = true
	}
	if len(deadlines) < 90 {
		t.Fatal("fleet renewal is not spread")
	}
}
