//go:build integration

package postgres

import (
	"Heimdall/internal/application"
	"Heimdall/internal/identity"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestAnnouncementDeletionRequiresPermissionCurrentVersionAndKeepsAudit(t *testing.T) {
	ctx, s, admin, _ := isolatedStore(t)
	a := application.Announcement{ID: uuid.NewString(), Title: "Maintenance", Markdown: "Scheduled restart", Severity: "info", Enabled: true}
	if _, err := s.SaveAnnouncement(ctx, admin, a); err != nil {
		t.Fatal(err)
	}
	user, _, err := s.CreateUser(ctx, admin, identity.User{Login: "announcement_reader", Kind: "service"}, "")
	if err != nil {
		t.Fatal(err)
	}
	reader, err := s.Principal(ctx, user.ID, "", "api")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.DeleteAnnouncement(ctx, reader, a.ID, 1); !errors.Is(err, application.ErrForbidden) {
		t.Fatalf("reader deleted announcement: %v", err)
	}
	a.Version = 1
	a.Title = "Rescheduled maintenance"
	if _, err = s.SaveAnnouncement(ctx, admin, a); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DeleteAnnouncement(ctx, admin, a.ID, 1); !errors.Is(err, application.ErrConflict) {
		t.Fatalf("stale delete accepted: %v", err)
	}
	if _, err = s.DeleteAnnouncement(ctx, admin, a.ID, 0); err == nil {
		t.Fatal("unversioned deletion accepted")
	}
	operation, err := s.DeleteAnnouncement(ctx, admin, a.ID, 2)
	if err != nil {
		t.Fatal(err)
	}
	for _, all := range []bool{false, true} {
		items, listErr := s.Announcements(ctx, admin, all)
		if listErr != nil || len(items) != 0 {
			t.Fatalf("deleted message remains visible: all=%v, err=%v", all, listErr)
		}
	}
	var count int
	if err = s.Pool.QueryRow(ctx, "SELECT count(*) FROM audit_events WHERE action='announcement.delete' AND resource_id=$1 AND actor_id=$2", a.ID, admin.UserID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("missing or duplicated deletion audit: %d, %v", count, err)
	}
	if err = s.Pool.QueryRow(ctx, "SELECT count(*) FROM sync_targets WHERE operation_id=$1", operation).Scan(&count); err != nil || count != 0 {
		t.Fatalf("announcement deletion scheduled native changes: %d, %v", count, err)
	}
	if _, err = s.DeleteAnnouncement(ctx, admin, a.ID, 2); !errors.Is(err, application.ErrNotFound) {
		t.Fatalf("missing announcement did not return not found: %v", err)
	}
}
