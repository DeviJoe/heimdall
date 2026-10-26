package postgres

import (
	"Heimdall/internal/authorization"
	"Heimdall/internal/identity"
	"Heimdall/internal/platform/security"
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

func (s *Store) ProvisionOIDC(ctx context.Context, issuer, subject, login, name string, mfa bool) (identity.User, error) {
	var u identity.User
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return u, err
	}
	defer tx.Rollback(ctx)
	var rev int64
	if err = tx.QueryRow(ctx, "UPDATE system_state SET revision=revision+1 RETURNING revision").Scan(&rev); err != nil {
		return u, err
	}
	var id string
	err = tx.QueryRow(ctx, "SELECT user_id FROM identities WHERE provider=$1 AND subject=$2", "oidc:"+issuer, subject).Scan(&id)
	if err == nil {
		return s.User(ctx, id)
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return u, err
	}
	if login == "" {
		login = "oidc_" + security.HashToken(issuer + ":" + subject)[:12]
	}
	u = identity.User{ID: uuid.NewString(), Login: login, DisplayName: name, Status: "active", Home: "/home/" + login, Shell: "/bin/bash", RequireMFA: mfa, Source: "oidc:" + issuer}
	if err = tx.QueryRow(ctx, "SELECT nextval('posix_ids')::int").Scan(&u.UID); err != nil {
		return u, err
	}
	u.GID = u.UID
	if err = u.Validate(); err != nil {
		return u, err
	}
	_, err = tx.Exec(ctx, "INSERT INTO users(id,login,display_name,status,uid,gid,home,shell,source,require_mfa) VALUES($1,$2,$3,'active',$4,$4,$5,$6,$7,$8)", u.ID, u.Login, u.DisplayName, u.UID, u.Home, u.Shell, u.Source, mfa)
	if err != nil {
		return u, err
	}
	_, err = tx.Exec(ctx, "INSERT INTO identities(provider,subject,user_id) VALUES($1,$2,$3)", "oidc:"+issuer, subject, u.ID)
	if err != nil {
		return u, err
	}
	_, err = s.record(ctx, tx, authorization.Principal{UserID: "oidc:" + issuer}, change{Kind: "user.provision", Resource: u.ID, UserID: u.ID}, rev)
	return u, err
}
