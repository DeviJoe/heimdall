package postgres

import (
	"Heimdall/internal/application"
	"Heimdall/internal/authorization"
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"strings"
)

func (s *Store) Passkeys(ctx context.Context, p authorization.Principal, id string) ([]application.Passkey, error) {
	if p.UserID != id && !p.Allowed("users.read", "*") {
		return nil, ErrForbidden
	}
	if p.TokenID != "" && !p.Self(id) && !p.Allowed("users.read", "*") {
		return nil, ErrForbidden
	}
	rows, err := s.Pool.Query(ctx, "SELECT id,name,created_at,last_used FROM webauthn_credentials WHERE user_id=$1 ORDER BY created_at DESC NULLS LAST,id LIMIT 100", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []application.Passkey{}
	for rows.Next() {
		var k application.Passkey
		if err = rows.Scan(&k.ID, &k.Name, &k.CreatedAt, &k.LastUsed); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}
func (s *Store) RenamePasskey(ctx context.Context, p authorization.Principal, id, key, name string) error {
	name = strings.TrimSpace(name)
	if len(name) < 1 || len(name) > 100 {
		return errors.New("passkey name must be 1–100 characters")
	}
	permission := "users.manage"
	if p.UserID == id {
		permission = ""
	}
	_, err := s.mutate(ctx, p, change{Kind: "passkey.rename", Resource: key, Permission: permission, Group: "*", UserID: id, TransportOnly: true}, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, "UPDATE webauthn_credentials SET name=$3 WHERE id=$1 AND user_id=$2", key, id, name)
		if err == nil && tag.RowsAffected() != 1 {
			return ErrNotFound
		}
		return err
	})
	return err
}
func (s *Store) RemoveFactor(ctx context.Context, p authorization.Principal, id, key string) (string, error) {
	permission := "users.manage"
	if p.UserID == id {
		permission = ""
	}
	return s.mutate(ctx, p, change{Kind: "mfa.reset", Resource: id, Permission: permission, Group: "*", UserID: id}, func(tx pgx.Tx) error {
		var err error
		if key == "totp" {
			_, err = tx.Exec(ctx, "UPDATE users SET totp_secret='',last_totp_step=0 WHERE id=$1", id)
		} else {
			tag, e := tx.Exec(ctx, "DELETE FROM webauthn_credentials WHERE user_id=$1 AND id=$2", id, key)
			err = e
			if err == nil && tag.RowsAffected() != 1 {
				return ErrNotFound
			}
		}
		if err != nil {
			return err
		}
		if p.UserID == id {
			var satisfied bool
			if err = tx.QueryRow(ctx, "SELECT mfa_satisfied($1)", id).Scan(&satisfied); err != nil {
				return err
			}
			if !satisfied {
				return errors.New("Фактор обязателен по действующей политике; отвязка запрещена. Для восстановления обратитесь к администратору")
			}
		}
		if _, err = tx.Exec(ctx, "UPDATE users SET auth_version=auth_version+1 WHERE id=$1", id); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, "DELETE FROM recovery_codes c USING users u WHERE c.user_id=$1 AND u.id=c.user_id AND u.totp_secret='' AND NOT EXISTS(SELECT 1 FROM webauthn_credentials w WHERE w.user_id=u.id)", id)
		return err
	})
}
func (s *Store) MovePeople(ctx context.Context, p authorization.Principal, source, target string, ids []string) (string, error) {
	if source == target || target == "" || len(ids) < 1 || len(ids) > 500 {
		return "", errors.New("select a different destination and 1–500 users")
	}
	return s.mutate(ctx, p, change{Kind: "user_group.update", Resource: target, Permission: "users.manage", Group: "*", All: true}, func(tx pgx.Tx) error {
		var purpose string
		if err := tx.QueryRow(ctx, "SELECT purpose FROM user_groups WHERE id=$1", target).Scan(&purpose); err != nil {
			return failure(err)
		}
		affected := []string{target}
		if source != "" {
			affected = append(affected, source)
		}
		if purpose == "factor_policy" {
			rows, err := tx.Query(ctx, "SELECT DISTINCT g.id FROM user_groups g JOIN user_group_members m ON m.group_id=g.id WHERE g.purpose='factor_policy' AND m.user_id=ANY($1::uuid[])", ids)
			if err != nil {
				return err
			}
			for rows.Next() {
				var id string
				if err = rows.Scan(&id); err != nil {
					rows.Close()
					return err
				}
				affected = append(affected, id)
			}
			err = rows.Err()
			rows.Close()
			if err != nil {
				return err
			}
			var service bool
			if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE id=ANY($1::uuid[]) AND kind='service')", ids).Scan(&service); err != nil {
				return err
			}
			if service {
				return errors.New("factor enrollment groups accept human accounts only")
			}
		}
		if err := s.authorizePeopleMembership(ctx, tx, p, affected); err != nil {
			return err
		}
		var count int
		if err := tx.QueryRow(ctx, "SELECT count(*) FROM users WHERE id=ANY($1::uuid[]) AND status<>'deleted'", ids).Scan(&count); err != nil {
			return err
		}
		if count != len(ids) {
			return errors.New("duplicate or unknown users")
		}
		if source != "" {
			if err := tx.QueryRow(ctx, "SELECT count(*) FROM user_group_members WHERE group_id=$1 AND user_id=ANY($2::uuid[])", source, ids).Scan(&count); err != nil {
				return err
			}
			if count != len(ids) {
				return errors.New("some selected users are no longer in the source group; refresh")
			}
		}
		// The four enrollment cohorts are mutually exclusive. General group and
		// direct-user policies still intersect, never weaken during a cohort move.
		if purpose == "factor_policy" {
			if _, err := tx.Exec(ctx, "DELETE FROM user_group_members m USING user_groups g WHERE m.group_id=g.id AND g.purpose='factor_policy' AND m.user_id=ANY($1::uuid[])", ids); err != nil {
				return err
			}
		} else if source != "" {
			if _, err := tx.Exec(ctx, "DELETE FROM user_group_members WHERE group_id=$1 AND user_id=ANY($2::uuid[])", source, ids); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, "INSERT INTO user_group_members SELECT $1,id FROM unnest($2::uuid[]) id ON CONFLICT DO NOTHING", target, ids); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "UPDATE users SET auth_version=auth_version+1 WHERE id=ANY($1::uuid[])", ids); err != nil {
			return err
		}
		if err := requireAdministrator(ctx, tx); err != nil {
			return err
		}
		return revokeNonSK(ctx, tx)
	})
}

func (s *Store) RemovePeople(ctx context.Context, p authorization.Principal, group string, ids []string) (string, error) {
	if len(ids) < 1 || len(ids) > 500 {
		return "", errors.New("select 1–500 users")
	}
	return s.mutate(ctx, p, change{Kind: "user_group.update", Resource: group, Permission: "users.manage", Group: "*", All: true}, func(tx pgx.Tx) error {
		if err := s.authorizePeopleMembership(ctx, tx, p, []string{group}); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "UPDATE users SET auth_version=auth_version+1 WHERE id=ANY($1::uuid[]) AND id IN(SELECT user_id FROM user_group_members WHERE group_id=$2)", ids, group); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, "DELETE FROM user_group_members WHERE group_id=$1 AND user_id=ANY($2::uuid[])", group, ids); err != nil {
			return err
		}
		return requireAdministrator(ctx, tx)
	})
}
