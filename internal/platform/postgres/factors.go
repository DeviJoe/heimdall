package postgres

import (
	"Heimdall/internal/authorization"
	"Heimdall/internal/platform/security"
	"context"
	"errors"
)

func (s *Store) EnableTOTP(ctx context.Context, id, secret string, recovery []string) error {
	return s.enableFactor(ctx, id, "", nil, secret, recovery, nil)
}
func (s *Store) EnableWebAuthn(ctx context.Context, id, keyID string, credential []byte, recovery []string) error {
	return s.enableFactor(ctx, id, keyID, credential, "", recovery, nil)
}
func (s *Store) enableFactor(ctx context.Context, id, keyID string, credential []byte, secret string, recovery []string, expectedVersion *int64) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var rev int64
	if err = tx.QueryRow(ctx, "UPDATE system_state SET revision=revision+1 RETURNING revision").Scan(&rev); err != nil {
		return err
	}
	var status, current string
	var version int64
	if err = tx.QueryRow(ctx, "SELECT status,totp_secret,auth_version FROM users WHERE id=$1 FOR UPDATE", id).Scan(&status, &current, &version); err != nil || status != "active" {
		return ErrForbidden
	}
	if secret != "" {
		if expectedVersion == nil && current != "" {
			return errors.New("TOTP already configured")
		}
		if expectedVersion != nil && (current == "" || version != *expectedVersion) {
			return errors.New("Факторы или права изменились. Начните замену TOTP заново")
		}
		_, err = tx.Exec(ctx, "UPDATE users SET totp_secret=$2,auth_version=auth_version+1,last_totp_step=floor(extract(epoch FROM now())/30)::bigint WHERE id=$1", id, secret)
	} else {
		var count int
		if err = tx.QueryRow(ctx, "SELECT count(*) FROM webauthn_credentials WHERE user_id=$1", id).Scan(&count); err != nil {
			return err
		}
		if count >= 100 {
			return errors.New("passkey limit reached (100)")
		}
		_, err = tx.Exec(ctx, "INSERT INTO webauthn_credentials(id,user_id,credential) VALUES($1,$2,$3)", keyID, id, credential)
		if err == nil {
			_, err = tx.Exec(ctx, "UPDATE users SET auth_version=auth_version+1 WHERE id=$1", id)
		}
	}
	if err != nil {
		return err
	}
	if len(recovery) != 10 {
		return errors.New("ten recovery hashes required")
	}
	if _, err = tx.Exec(ctx, "DELETE FROM recovery_codes WHERE user_id=$1", id); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, "INSERT INTO recovery_codes(user_id,hash) SELECT $1,hash FROM unnest($2::text[]) hash", id, recovery); err != nil {
		return err
	}
	_, err = s.record(ctx, tx, authorization.Principal{UserID: id}, change{Kind: "user.factor", Resource: id, UserID: id}, rev)
	return err
}
func (s *Store) ConsumeRecoveryCode(ctx context.Context, id, code string) bool {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return false
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, "UPDATE recovery_codes c SET used_at=now() FROM users u WHERE c.user_id=$1 AND c.hash=$2 AND c.used_at IS NULL AND u.id=c.user_id AND u.status='active'", id, security.HashToken(code))
	if err != nil || tag.RowsAffected() != 1 {
		return false
	}
	if _, err = tx.Exec(ctx, "INSERT INTO audit_events(actor_id,channel,action,resource_id) VALUES($1,'web','mfa.recovery_code',$1)", id); err != nil {
		return false
	}
	return tx.Commit(ctx) == nil
}

func (s *Store) RotateTOTP(ctx context.Context, id string, version int64, secret string, recovery []string) error {
	if secret == "" {
		return errors.New("new TOTP secret required")
	}
	return s.enableFactor(ctx, id, "", nil, secret, recovery, &version)
}
