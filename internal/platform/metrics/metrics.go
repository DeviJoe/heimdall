package metrics

import (
	"Heimdall/internal/application"
	"Heimdall/internal/platform/config"
	"Heimdall/internal/platform/security"
	"context"
	"crypto/subtle"
	"encoding/json"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"
)

type Repository interface {
	Settings(context.Context) (application.Settings, error)
	EnforceKeyPolicy(context.Context, bool) error
	Detect(context.Context, time.Duration, time.Duration, time.Duration) error
	Metrics(context.Context) (application.MetricState, error)
}
type Monitor struct {
	FleetChanged    func()
	QueueConnected  func() bool
	ConnectionCount func() int
	Store           Repository
	Config          config.Config
	mu              sync.RWMutex
	settings        application.Settings
	state           application.MetricState
	collected       time.Time
	detector        time.Time
	descs           map[string]*prometheus.Desc
}

func (m *Monitor) ApplyTimeout() time.Duration {
	m.mu.RLock()
	seconds := m.settings.ApplyTimeoutSeconds
	m.mu.RUnlock()
	if seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	return m.Config.Sync.ApplyTimeout
}

func New(store Repository, c config.Config) *Monitor {
	m := &Monitor{Store: store, Config: c, descs: map[string]*prometheus.Desc{}}
	names := map[string]string{"heimdall_sync_stalled_after_seconds": "Runtime synchronization stall threshold", "heimdall_revocation_alert_after_seconds": "Runtime revocation alert threshold", "heimdall_sync_pending_nodes": "Nodes awaiting a confirmed Linux revision", "heimdall_sync_oldest_pending_seconds": "Oldest unconfirmed synchronization age", "heimdall_revocation_pending_nodes": "Nodes with unconfirmed revocations", "heimdall_outbox_oldest_pending_seconds": "Durable outbox age", "heimdall_notification_oldest_pending_seconds": "Oldest undelivered notification age", "heimdall_incidents_active": "Active incidents", "heimdall_metrics_snapshot_timestamp_seconds": "Last successful metrics snapshot", "heimdall_sync_detector_timestamp_seconds": "Last successful incident detection"}
	for name, help := range names {
		m.descs[name] = prometheus.NewDesc(name, help, nil, nil)
	}
	m.descs["heimdall_nodes_connectivity"] = prometheus.NewDesc("heimdall_nodes_connectivity", "Nodes by heartbeat connectivity", []string{"state"}, nil)
	m.descs["heimdall_certificates_pending"] = prometheus.NewDesc("heimdall_certificates_pending", "Nodes awaiting the current certificate lifetime policy", nil, nil)
	m.descs["heimdall_certificate_rollout_oldest_seconds"] = prometheus.NewDesc("heimdall_certificate_rollout_oldest_seconds", "Age of the oldest pending certificate policy", nil, nil)
	m.descs["heimdall_nodes"] = prometheus.NewDesc("heimdall_nodes", "Nodes by synchronization phase", []string{"phase"}, nil)
	m.descs["heimdall_directory_last_success_timestamp_seconds"] = prometheus.NewDesc("heimdall_directory_last_success_timestamp_seconds", "Last fully completed directory synchronization", []string{"provider"}, nil)
	m.descs["heimdall_directory_failed"] = prometheus.NewDesc("heimdall_directory_failed", "Directory synchronization is failing", []string{"provider"}, nil)
	m.descs["heimdall_queue_connected"] = prometheus.NewDesc("heimdall_queue_connected", "RabbitMQ synchronization transport availability", nil, nil)
	m.descs["heimdall_agent_connections"] = prometheus.NewDesc("heimdall_agent_connections", "Agent streams owned by this control plane instance", nil, nil)
	return m
}
func (m *Monitor) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range m.descs {
		ch <- d
	}
}
func (m *Monitor) Collect(ch chan<- prometheus.Metric) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.ConnectionCount != nil {
		ch <- prometheus.MustNewConstMetric(m.descs["heimdall_agent_connections"], prometheus.GaugeValue, float64(m.ConnectionCount()))
	}
	if m.QueueConnected != nil {
		value := 0.
		if m.QueueConnected() {
			value = 1
		}
		ch <- prometheus.MustNewConstMetric(m.descs["heimdall_queue_connected"], prometheus.GaugeValue, value)
	}
	for state, count := range m.state.Connectivity {
		ch <- prometheus.MustNewConstMetric(m.descs["heimdall_nodes_connectivity"], prometheus.GaugeValue, float64(count), state)
	}
	ch <- prometheus.MustNewConstMetric(m.descs["heimdall_certificates_pending"], prometheus.GaugeValue, float64(m.state.CertificatesPending))
	ch <- prometheus.MustNewConstMetric(m.descs["heimdall_certificate_rollout_oldest_seconds"], prometheus.GaugeValue, m.state.CertificatesOldest)
	for phase, count := range m.state.Nodes {
		ch <- prometheus.MustNewConstMetric(m.descs["heimdall_nodes"], prometheus.GaugeValue, float64(count), phase)
	}
	for _, provider := range m.Config.LDAP {
		status := m.state.Directories[provider.ID]
		last := float64(0)
		failed := float64(0)
		if status.LastSuccess != nil {
			last = float64(status.LastSuccess.Unix())
		}
		if status.Phase == "failed" {
			failed = 1
		}
		ch <- prometheus.MustNewConstMetric(m.descs["heimdall_directory_last_success_timestamp_seconds"], prometheus.GaugeValue, last, provider.ID)
		ch <- prometheus.MustNewConstMetric(m.descs["heimdall_directory_failed"], prometheus.GaugeValue, failed, provider.ID)
	}
	values := map[string]float64{"heimdall_sync_stalled_after_seconds": float64(m.settings.StalledSeconds), "heimdall_revocation_alert_after_seconds": float64(m.settings.RevocationAlertSeconds), "heimdall_sync_pending_nodes": float64(m.state.Pending), "heimdall_sync_oldest_pending_seconds": m.state.Oldest, "heimdall_revocation_pending_nodes": float64(m.state.Revocations), "heimdall_outbox_oldest_pending_seconds": m.state.OutboxOldest, "heimdall_notification_oldest_pending_seconds": m.state.NotificationOldest, "heimdall_incidents_active": float64(m.state.Incidents)}
	if !m.collected.IsZero() {
		values["heimdall_metrics_snapshot_timestamp_seconds"] = float64(m.collected.Unix())
	}
	if !m.detector.IsZero() {
		values["heimdall_sync_detector_timestamp_seconds"] = float64(m.detector.Unix())
	}
	for name, value := range values {
		ch <- prometheus.MustNewConstMetric(m.descs[name], prometheus.GaugeValue, value)
	}
}
func (m *Monitor) Run(ctx context.Context) {
	lastConnectivity := ""
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
		settings, err := m.Store.Settings(bounded)
		if err != nil {
			slog.Error("runtime settings unavailable", "error", err)
			cancel()
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
			continue
		}
		m.mu.Lock()
		m.settings = settings
		m.mu.Unlock()
		if err := m.Store.EnforceKeyPolicy(bounded, settings.RequireSK); err != nil {
			slog.Error("key expiry reconciliation failed", "error", err)
		}
		if err := m.Store.Detect(bounded, time.Duration(settings.StalledSeconds)*time.Second, time.Duration(settings.OfflineSeconds)*time.Second, time.Duration(settings.RevocationAlertSeconds)*time.Second); err != nil {
			slog.Error("sync detector failed", "error", err)
		} else {
			m.mu.Lock()
			m.detector = time.Now()
			m.mu.Unlock()
		}
		state, err := m.Store.Metrics(bounded)
		if err != nil {
			slog.Error("metrics snapshot failed", "error", err)
		} else {
			m.mu.Lock()
			m.state = state
			m.collected = time.Now()
			m.mu.Unlock()
			connectivity, _ := json.Marshal(state.Connectivity)
			if string(connectivity) != lastConnectivity {
				lastConnectivity = string(connectivity)
				if m.FleetChanged != nil {
					m.FleetChanged()
				}
			}
		}
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
func (m *Monitor) Handler() http.Handler {
	registry := prometheus.NewRegistry()
	registry.MustRegister(m)
	registry.MustRegister(prometheus.NewGoCollector())
	registry.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))
	handler := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/metrics" {
			http.NotFound(w, r)
			return
		}
		if env := m.Config.Metrics.PasswordHashEnv; env != "" {
			user, password, ok := r.BasicAuth()
			if !ok || subtle.ConstantTimeCompare([]byte(user), []byte(os.Getenv(m.Config.Metrics.UsernameEnv))) != 1 || subtle.ConstantTimeCompare([]byte(security.HashToken(password)), []byte(os.Getenv(env))) != 1 {
				w.Header().Set("WWW-Authenticate", `Basic realm="Heimdall metrics"`)
				http.Error(w, "credentials required", 401)
				return
			}
		}
		handler.ServeHTTP(w, r)
	})
}
