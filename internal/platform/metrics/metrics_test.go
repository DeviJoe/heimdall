package metrics

import (
	"Heimdall/internal/application"
	"Heimdall/internal/platform/config"
	"Heimdall/internal/platform/security"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestProtectedMetricsExposeConnectivityAndCurrentThresholds(t *testing.T) {
	t.Setenv("TEST_METRICS_USER", "monitor")
	t.Setenv("TEST_METRICS_HASH", security.HashToken("test-password"))
	c := config.Config{}
	c.Metrics.UsernameEnv = "TEST_METRICS_USER"
	c.Metrics.PasswordHashEnv = "TEST_METRICS_HASH"
	m := New(nil, c)
	m.state = application.MetricState{CertificatesPending: 3, CertificatesOldest: 120, Connectivity: map[string]int{"offline": 2}, Nodes: map[string]int{"pending": 1}}
	m.settings = application.Settings{StalledSeconds: 75, RevocationAlertSeconds: 30}
	m.collected = time.Now()
	m.detector = time.Now()
	for _, allowed := range []bool{false, true} {
		r := httptest.NewRequest("GET", "/metrics", nil)
		if allowed {
			r.SetBasicAuth("monitor", "test-password")
		}
		w := httptest.NewRecorder()
		m.Handler().ServeHTTP(w, r)
		if !allowed {
			if w.Code != 401 {
				t.Fatal("metrics exposed without credentials")
			}
			continue
		}
		if w.Code != 200 {
			t.Fatal(w.Code)
		}
		for _, line := range []string{`heimdall_certificates_pending 3`, `heimdall_certificate_rollout_oldest_seconds 120`, `heimdall_nodes_connectivity{state="offline"} 2`, `heimdall_sync_stalled_after_seconds 75`, `heimdall_revocation_alert_after_seconds 30`} {
			if !strings.Contains(w.Body.String(), line) {
				t.Fatalf("missing metric %s", line)
			}
		}
	}
}
