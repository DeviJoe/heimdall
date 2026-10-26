package postgres

import (
	"Heimdall/internal/application"
	"Heimdall/internal/authorization"
	"Heimdall/internal/platform/security"
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"time"
)

type Token = application.Token

func (s *Store) Bearer(ctx context.Context, secret, audience string) (authorization.Principal, error) {
	var userID, id string
	err := s.Pool.QueryRow(ctx, "SELECT id,user_id FROM api_tokens WHERE hash=$1 AND revoked_at IS NULL AND expires_at>now()", security.HashToken(secret)).Scan(&id, &userID)
	if err != nil {
		return authorization.Principal{}, ErrForbidden
	}
	p, err := s.Principal(ctx, userID, id, audience)
	if err != nil {
		return p, err
	}
	_, _ = s.Pool.Exec(ctx, "UPDATE api_tokens SET last_used=now() WHERE id=$1 AND (last_used IS NULL OR last_used<now()-interval '5 minutes')", id)
	return p, nil
}
func (s *Store) Tokens(ctx context.Context, p authorization.Principal) ([]Token, error) {
	rows, err := s.Pool.Query(ctx, "SELECT id,user_id,name,audiences,scopes,groups,expires_at,revoked_at,last_used FROM api_tokens WHERE expires_at>now() AND revoked_at IS NULL AND (user_id=$1 OR ($2 AND user_id IN (SELECT id FROM users WHERE kind='service'))) ORDER BY created_at DESC LIMIT 100", p.UserID, p.Allowed("tokens.manage", "*"))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Token{}
	for rows.Next() {
		var t Token
		var a, b, c []byte
		if err = rows.Scan(&t.ID, &t.UserID, &t.Name, &a, &b, &c, &t.ExpiresAt, &t.RevokedAt, &t.LastUsed); err != nil {
			return nil, err
		}
		json.Unmarshal(a, &t.Audiences)
		json.Unmarshal(b, &t.Scopes)
		json.Unmarshal(c, &t.Groups)
		out = append(out, t)
	}
	return out, rows.Err()
}
func (s *Store) CreateToken(ctx context.Context, p authorization.Principal, t Token) (Token, string, error) {
	if p.Restricted {
		return t, "", ErrForbidden
	}
	if len(t.Name) == 0 || len(t.Name) > 100 || !t.ExpiresAt.After(time.Now()) || t.ExpiresAt.After(time.Now().Add(30*24*time.Hour)) {
		return t, "", errors.New("invalid token name or TTL (maximum 30 days)")
	}
	if len(t.Audiences) == 0 || len(t.Scopes) == 0 {
		return t, "", errors.New("audience and scopes required")
	}
	for _, a := range t.Audiences {
		if a != "api" && a != "mcp" {
			return t, "", errors.New("invalid token audience")
		}
	}
	if len(t.Groups) == 0 {
		t.Groups = []string{"*"}
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return t, "", err
	}
	defer tx.Rollback(ctx)
	if _, err = tx.Exec(ctx, "SELECT id FROM users WHERE id=$1 FOR UPDATE", p.UserID); err != nil {
		return t, "", err
	}
	current, err := s.principal(ctx, tx, p.UserID, p.TokenID, p.Audience)
	if err != nil {
		return t, "", err
	}
	if t.UserID == "" {
		t.UserID = p.UserID
	}
	owner := current
	if t.UserID != p.UserID {
		if !current.Allowed("tokens.manage", "*") || !current.Allowed("users.manage", "*") {
			return t, "", ErrForbidden
		}
		var service bool
		if err = tx.QueryRow(ctx, "SELECT kind='service' AND status='active' FROM users WHERE id=$1", t.UserID).Scan(&service); err != nil || !service {
			return t, "", ErrForbidden
		}
		owner, err = s.principal(ctx, tx, t.UserID, "", "api")
		if err != nil {
			return t, "", err
		}
	}
	for _, scope := range t.Scopes {
		for _, group := range t.Groups {
			if scope == "self" {
				if t.UserID != p.UserID || !current.Self(p.UserID) {
					return t, "", ErrForbidden
				}
			} else if !current.Allowed(scope, group) || !owner.Allowed(scope, group) {
				return t, "", ErrForbidden
			}
		}
	}
	t.ID = uuid.NewString()
	secret := "lnp_" + security.Random(32)
	_, err = tx.Exec(ctx, "INSERT INTO api_tokens(id,user_id,name,hash,audiences,scopes,groups,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8)", t.ID, t.UserID, t.Name, security.HashToken(secret), jsonValue(t.Audiences), jsonValue(t.Scopes), jsonValue(t.Groups), t.ExpiresAt)
	if err != nil {
		return t, "", err
	}
	_, err = tx.Exec(ctx, "INSERT INTO audit_events(actor_id,token_id,channel,action,resource_id) VALUES($1,$2,$3,'token.create',$4)", p.UserID, p.TokenID, channel(p), t.ID)
	if err != nil {
		return t, "", err
	}
	return t, secret, tx.Commit(ctx)
}
func (s *Store) RevokeToken(ctx context.Context, p authorization.Principal, id string) error {
	current, err := s.Principal(ctx, p.UserID, p.TokenID, p.Audience)
	if err != nil {
		return err
	}
	tag, err := s.Pool.Exec(ctx, "UPDATE api_tokens SET revoked_at=now() WHERE id=$1 AND (user_id=$2 OR ($3 AND user_id IN (SELECT id FROM users WHERE kind='service')))", id, p.UserID, current.Allowed("tokens.manage", "*"))
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrForbidden
	}
	return s.Audit(ctx, p, "token.revoke", id)
}
