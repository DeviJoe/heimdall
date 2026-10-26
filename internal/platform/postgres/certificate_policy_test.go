//go:build integration

package postgres

import (
	"Heimdall/internal/application"
	"Heimdall/internal/synchronization"
	"errors"
	"github.com/google/uuid"
	"testing"
	"time"
)

func TestCertificateLifetimeChangeIsVersionedAndTracksOfflineNodes(t *testing.T) {
	ctx, s, admin, join := isolatedStore(t)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	settings, err := s.Settings(ctx)
	must(err)
	if settings.NodeCertificateTTLSeconds != synchronization.DefaultNodeCertificateTTLSeconds {
		t.Fatal("default certificate TTL is not ten years")
	}
	ids := []string{uuid.NewString(), uuid.NewString()}
	for _, id := range ids {
		_, err = s.Enroll(ctx, join, "policy-node-"+id, "original", time.Now().Add(24*time.Hour), id)
		must(err)
		must(s.NodeCertificate(ctx, id, "original", "current", time.Now().Add(3650*24*time.Hour), settings.CertificatePolicyVersion))
		_, err = s.ConnectNode(ctx, id, "current")
		must(err)
	}
	settings, err = s.Settings(ctx)
	must(err)
	if settings.CertificatesPending != 0 || settings.CertificatesTotal != 2 {
		t.Fatal("initial rollout status incorrect")
	}
	old := settings
	settings.NodeCertificateTTLSeconds = 365 * 86400
	_, err = s.SaveSettings(ctx, admin, settings)
	must(err)
	current, err := s.Settings(ctx)
	must(err)
	if current.CertificatePolicyVersion != old.CertificatePolicyVersion+1 || current.CertificatesPending != 2 {
		t.Fatal("TTL update did not queue every node")
	}
	if _, err = s.SaveSettings(ctx, admin, old); !errors.Is(err, application.ErrConflict) {
		t.Fatal("stale settings replaced certificate policy")
	}
	for _, id := range ids {
		state, err := s.Snapshot(ctx, id)
		must(err)
		if state.CertificatePolicy.Version != current.CertificatePolicyVersion || state.CertificatePolicy.TTLSeconds != current.NodeCertificateTTLSeconds {
			t.Fatal("snapshot does not carry current signed certificate policy")
		}
	}
	// A response issued before a concurrent policy change cannot report the
	// node as current. It leaves the current serial and rollout unchanged.
	if err = s.NodeCertificate(ctx, ids[0], "current", "stale-issue", time.Now().Add(time.Hour), old.CertificatePolicyVersion); !errors.Is(err, ErrForbidden) {
		t.Fatal("old policy renewal marked the node current")
	}
	if !s.NodeAllowed(ctx, ids[0], "current") {
		t.Fatal("rejected stale renewal replaced the active identity")
	}
	must(s.NodeCertificate(ctx, ids[0], "current", "one-year", time.Now().Add(365*24*time.Hour), current.CertificatePolicyVersion))
	unconfirmed, err := s.Settings(ctx)
	must(err)
	if unconfirmed.CertificatesPending != 2 {
		t.Fatal("issued certificate reported as installed before proof of possession")
	}
	_, err = s.ConnectNode(ctx, ids[0], "one-year")
	must(err)
	current, err = s.Settings(ctx)
	must(err)
	if current.CertificatesPending != 1 {
		t.Fatal("offline node disappeared from rollout")
	}
	metrics, err := s.Metrics(ctx)
	must(err)
	if metrics.CertificatesPending != 1 {
		t.Fatal("metrics do not expose pending certificate policy")
	}
	current.SwaggerEnabled = !current.SwaggerEnabled
	_, err = s.SaveSettings(ctx, admin, current)
	must(err)
	after, err := s.Settings(ctx)
	must(err)
	if after.CertificatePolicyVersion != current.CertificatePolicyVersion {
		t.Fatal("unrelated setting forced certificate reissue")
	}
	must(s.NodeCertificate(ctx, ids[1], "current", "returned", time.Now().Add(365*24*time.Hour), after.CertificatePolicyVersion))
	_, err = s.ConnectNode(ctx, ids[1], "returned")
	must(err)
	completed, err := s.Settings(ctx)
	must(err)
	if completed.CertificatesPending != 0 {
		t.Fatal("reconnected node did not complete rollout")
	}
}
