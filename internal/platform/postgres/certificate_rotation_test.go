//go:build integration

package postgres

import (
	"errors"
	"github.com/google/uuid"
	"testing"
	"time"
)

func TestLostCertificateRenewalResponseCanRetryWithoutExtendingOverlap(t *testing.T) {
	ctx, s, admin, join := isolatedStore(t)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	id := uuid.NewString()
	policy, err := s.CertificatePolicy(ctx)
	must(err)
	_, err = s.Enroll(ctx, join, "rotation-node", "old", time.Now().Add(time.Hour), id)
	must(err)
	must(s.NodeCertificate(ctx, id, "old", "lost-response", time.Now().Add(24*time.Hour), policy.Version))
	if !s.NodeAllowed(ctx, id, "old") || !s.NodeAllowed(ctx, id, "lost-response") {
		t.Fatal("interrupted renewal stranded the agent")
	}
	var deadline time.Time
	must(s.Pool.QueryRow(ctx, "SELECT previous_cert_expires FROM nodes WHERE id=$1", id).Scan(&deadline))
	if deadline.After(time.Now().Add(15 * time.Minute)) {
		t.Fatal("overlap exceeds its limit")
	}
	// A retry uses the preceding credential; the overlap must not be renewed.
	must(s.NodeCertificate(ctx, id, "old", "retry", time.Now().Add(24*time.Hour), policy.Version))
	var retried time.Time
	must(s.Pool.QueryRow(ctx, "SELECT previous_cert_expires FROM nodes WHERE id=$1", id).Scan(&retried))
	if !retried.Equal(deadline) {
		t.Fatal("retry extended the old certificate window")
	}
	if s.NodeAllowed(ctx, id, "lost-response") {
		t.Fatal("unbounded certificate history accepted")
	}
	_, err = s.ConnectNode(ctx, id, "old")
	must(err)
	_, err = s.Pool.Exec(ctx, "UPDATE nodes SET previous_cert_expires=now()-interval '1 second' WHERE id=$1", id)
	must(err)
	if s.NodeAllowed(ctx, id, "old") {
		t.Fatal("expired overlap accepted")
	}
	if _, err = s.ConnectNode(ctx, id, "old"); !errors.Is(err, ErrForbidden) {
		t.Fatal("expired overlap connected")
	}
	if err = s.NodeCertificate(ctx, id, "old", "forbidden", time.Now().Add(time.Hour), policy.Version); !errors.Is(err, ErrForbidden) {
		t.Fatal("expired credential renewed")
	}
	recovery, err := s.CreateRecoveryToken(ctx, admin, id)
	must(err)
	must(s.RecoverNode(ctx, id, recovery, "recovered", time.Now().Add(time.Hour)))
	if s.NodeAllowed(ctx, id, "retry") || s.NodeAllowed(ctx, id, "old") || !s.NodeAllowed(ctx, id, "recovered") {
		t.Fatal("explicit recovery kept a preceding credential active")
	}
}
