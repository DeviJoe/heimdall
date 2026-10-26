//go:build integration || loadtest

package postgres

import (
	"Heimdall/internal/application"
	"Heimdall/internal/authorization"
	"Heimdall/internal/platform/security"
	"context"
	"github.com/jackc/pgx/v5/pgxpool"
	"os"
	"testing"
	"time"
)

func isolatedStore(t *testing.T, load ...bool) (context.Context, *Store, authorization.Principal, string) {
	t.Helper()
	dsn := os.Getenv("HEIMDALL_TEST_DATABASE_DSN")
	if dsn == "" {
		t.Skip("isolated PostgreSQL integration database not configured")
	}
	database := "linpam_test"
	if len(load) > 0 && load[0] {
		database = "linpam_load"
	}
	conf, err := pgxpool.ParseConfig(dsn)
	if err != nil || conf.ConnConfig.Database != database {
		t.Fatalf("only %s is permitted", database)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	store, err := New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	if err = store.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Pool.Exec(ctx, "TRUNCATE users,server_groups,roles,system_state,runtime_settings,user_groups,unix_groups,audit_events RESTART IDENTITY CASCADE"); err != nil {
		t.Fatal(err)
	}
	join := security.Random(32)
	if err = store.Bootstrap(ctx, "Integration-test-password", join); err != nil {
		t.Fatal(err)
	}
	if err = store.InitSettings(ctx, application.Settings{KeyTTLSeconds: 3600, StalledSeconds: 45, OfflineSeconds: 45, RevocationAlertSeconds: 20, SwaggerEnabled: true, MCPEnabled: true}); err != nil {
		t.Fatal(err)
	}
	a, err := store.Auth(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	p, err := store.Principal(ctx, a.User.ID, "", "api")
	if err != nil {
		t.Fatal(err)
	}
	return ctx, store, p, join
}
