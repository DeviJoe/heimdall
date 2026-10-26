package activity

import (
	"testing"
	"time"
)

func TestAuthenticationEvents(t *testing.T) {
	for _, test := range []struct{ line, kind, severity string }{{"Accepted publickey for alice from 10.0.0.1 port 42 ssh2", "managed_login", "info"}, {"Accepted password for unknown from 10.0.0.2 port 42 ssh2", "unmanaged_login", "warning"}, {"Accepted publickey for root from 10.0.0.3 port 42 ssh2", "unmanaged_login", "critical"}, {"Failed password for invalid user stranger from 10.0.0.4 port 52 ssh2", "failed_authentication", "info"}} {
		event, ok := Parse(test.line, func(login string) bool { return login == "alice" }, time.Now())
		if !ok || event.Kind != test.kind || event.Severity != test.severity {
			t.Fatalf("%q: %+v", test.line, event)
		}
	}
	if _, ok := Parse("arbitrary text", func(string) bool { return false }, time.Now()); ok {
		t.Fatal("unrecognized log accepted")
	}
}
