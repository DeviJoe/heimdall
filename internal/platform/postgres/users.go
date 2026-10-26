package postgres

import (
	"Heimdall/internal/application"
	"Heimdall/internal/authorization"
	"Heimdall/internal/credentials"
	"Heimdall/internal/identity"
	"Heimdall/internal/platform/security"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"time"
)

const userColumns = "id,login,display_name,status,uid,gid,home,shell,gecos,require_mfa,(totp_secret<>'' OR EXISTS(SELECT 1 FROM webauthn_credentials WHERE user_id=users.id)),auth_version,source,created_at,kind,mfa_policy,require_sk,totp_secret<>'',(SELECT count(*) FROM webauthn_credentials WHERE user_id=users.id),sync_to_nodes"

func scanUser(row pgx.Row) (identity.User, error) { return scanUserExtra(row) }
func scanUserExtra(row pgx.Row, extra ...any) (identity.User, error) {
	var u identity.User
	fields := []any{&u.ID, &u.Login, &u.DisplayName, &u.Status, &u.UID, &u.GID, &u.Home, &u.Shell, &u.GECOS, &u.RequireMFA, &u.MFAEnabled, &u.AuthVersion, &u.Source, &u.CreatedAt, &u.Kind, &u.MFAPolicy, &u.RequireSK, &u.TOTPEnabled, &u.PasskeyCount, &u.SyncToNodes}
	err := row.Scan(append(fields, extra...)...)
	return u, err
}
func (s *Store) User(ctx context.Context, id string) (identity.User, error) {
	u, err := scanUser(s.Pool.QueryRow(ctx, "SELECT "+userColumns+" FROM users WHERE id=$1", id))
	return u, failureIf(err)
}
func failureIf(err error) error {
	if err == nil {
		return nil
	}
	return failure(err)
}
func (s *Store) Users(ctx context.Context, p authorization.Principal) ([]identity.User, error) {
	if !p.Allowed("users.read", "*") {
		if !p.Self(p.UserID) {
			return nil, ErrForbidden
		}
		u, err := s.User(ctx, p.UserID)
		if err != nil {
			return nil, err
		}
		return []identity.User{u}, nil
	}
	rows, err := s.Pool.Query(ctx, "SELECT "+userColumns+" FROM users WHERE status<>'deleted' ORDER BY login LIMIT 500")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []identity.User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

type AuthRecord = application.AuthRecord

func (s *Store) Auth(ctx context.Context, login string) (AuthRecord, error) {
	var a AuthRecord
	u, err := scanUser(s.Pool.QueryRow(ctx, "SELECT "+userColumns+" FROM users WHERE login=$1 AND status='active' AND kind='human'", login))
	if err != nil {
		return a, ErrForbidden
	}
	a.User = u
	err = s.Pool.QueryRow(ctx, "SELECT password_hash,totp_secret,last_totp_step FROM users WHERE id=$1", u.ID).Scan(&a.PasswordHash, &a.TOTPSecret, &a.LastTOTPStep)
	return a, err
}
func (s *Store) CreateUser(ctx context.Context, p authorization.Principal, u identity.User, inviteHash string) (identity.User, string, error) {
	u.ID = uuid.NewString()
	u.Status = "invited"
	u.Source = "local"
	if u.Kind == "" {
		u.Kind = "human"
	}
	if u.Kind != "human" && u.Kind != "service" {
		return u, "", errors.New("invalid account kind")
	}
	if u.Kind == "service" {
		u.Status = "active"
		u.Source = "service"
		u.RequireMFA = false
		u.MFAPolicy = "none"
	}
	if u.MFAPolicy == "" {
		u.MFAPolicy = "none"
	}
	if u.Kind != "service" && u.RequireMFA && u.MFAPolicy == "none" {
		u.MFAPolicy = "any"
	}
	if u.MFAPolicy != "none" {
		u.RequireMFA = true
	}
	if !validMFAPolicy(u.MFAPolicy) {
		return u, "", errors.New("invalid enrollment policy")
	}
	op, err := s.mutate(ctx, p, change{Kind: "user.create", Resource: u.ID, Permission: "users.manage", Group: "*", UserID: u.ID}, func(tx pgx.Tx) error {
		if u.UID == 0 {
			if err := tx.QueryRow(ctx, "SELECT nextval('posix_ids')::int").Scan(&u.UID); err != nil {
				return err
			}
		}
		if u.GID == 0 {
			u.GID = u.UID
		}
		if u.Home == "" {
			u.Home = "/home/" + u.Login
		}
		if u.Shell == "" {
			u.Shell = "/bin/bash"
		}
		if err := u.Validate(); err != nil {
			return err
		}
		if err := s.authorizeUnixMembership(ctx, tx, p, nil, []int{u.GID}); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, "INSERT INTO users(id,login,display_name,status,uid,gid,home,shell,gecos,require_mfa,kind,mfa_policy,require_sk,sync_to_nodes) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)", u.ID, u.Login, u.DisplayName, u.Status, u.UID, u.GID, u.Home, u.Shell, u.GECOS, u.RequireMFA, u.Kind, u.MFAPolicy, u.RequireSK, u.SyncToNodes)
		if err != nil {
			return err
		}
		if u.Kind == "service" {
			return nil
		}
		_, err = tx.Exec(ctx, "INSERT INTO invitations(hash,user_id,expires_at) VALUES($1,$2,now()+interval '24 hours')", inviteHash, u.ID)
		return err
	})
	return u, op, err
}
func (s *Store) UpdateUser(ctx context.Context, p authorization.Principal, u identity.User, maintenance bool) (string, error) {
	if err := u.Validate(); err != nil {
		return "", err
	}
	if u.MFAPolicy == "" {
		if u.RequireMFA {
			u.MFAPolicy = "any"
		} else {
			u.MFAPolicy = "none"
		}
	}
	if !validMFAPolicy(u.MFAPolicy) {
		return "", errors.New("invalid enrollment policy")
	}
	return s.mutate(ctx, p, change{Kind: "user.update", Resource: u.ID, Permission: "users.manage", Group: "*", UserID: u.ID}, func(tx pgx.Tx) error {
		var uid, gid int
		var home, login string
		err := tx.QueryRow(ctx, "SELECT uid,gid,home,login FROM users WHERE id=$1 AND status<>'deleted'", u.ID).Scan(&uid, &gid, &home, &login)
		if err != nil {
			return failure(err)
		}
		if uid != u.UID || gid != u.GID || home != u.Home || login != u.Login {
			if gid != u.GID {
				if err := s.authorizeUnixMembership(ctx, tx, p, nil, []int{gid, u.GID}); err != nil {
					return err
				}
			}
			var provisioned, pending bool
			var status string
			if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM node_accounts WHERE user_id=$1),EXISTS(SELECT 1 FROM sync_targets t JOIN sync_operations o ON o.id=t.operation_id WHERE o.user_id=$1 AND t.status<>'applied'),status FROM users WHERE id=$1", u.ID).Scan(&provisioned, &pending, &status); err != nil {
				return err
			}
			if provisioned && (!maintenance || status != "disabled" || pending) {
				return errors.New("POSIX migration requires a disabled user, all prior node acknowledgements and maintenance=true")
			}
		}

		_, err = tx.Exec(ctx, "UPDATE users SET display_name=$2,shell=$3,gecos=$4,require_mfa=$5,auth_version=auth_version+1,login=$6,uid=$7,gid=$8,home=$9,mfa_policy=$10,require_sk=$11,sync_to_nodes=$12,linux_password_hash=CASE WHEN $12 THEN linux_password_hash ELSE '' END WHERE id=$1", u.ID, u.DisplayName, u.Shell, u.GECOS, u.RequireMFA, u.Login, u.UID, u.GID, u.Home, u.MFAPolicy, u.RequireSK, u.SyncToNodes)
		if err != nil {
			return err
		}
		return revokeNonSK(ctx, tx)
	})
}
func (s *Store) SetUserStatus(ctx context.Context, p authorization.Principal, id, status string) (string, error) {
	if status != "active" && status != "disabled" && status != "deleted" {
		return "", errors.New("invalid user status")
	}
	if id == p.UserID && status != "active" {
		return "", errors.New("cannot disable your own administrative session")
	}
	return s.mutate(ctx, p, change{Kind: "user." + status, Resource: id, Permission: "users.manage", Group: "*", UserID: id}, func(tx pgx.Tx) error {
		var current string
		if err := tx.QueryRow(ctx, "SELECT status FROM users WHERE id=$1", id).Scan(&current); err != nil {
			return failure(err)
		}
		if current == "deleted" {
			return errors.New("deleted users cannot be restored")
		}
		if status == "active" {
			var hasPassword bool
			if err := tx.QueryRow(ctx, "SELECT password_hash<>'' OR source<>'local' FROM users WHERE id=$1", id).Scan(&hasPassword); err != nil {
				return err
			}
			if !hasPassword {
				return errors.New("complete invitation before activation")
			}
		}
		_, err := tx.Exec(ctx, "UPDATE users SET status=$2,auth_version=auth_version+1,linux_password_hash=CASE WHEN $2='active' THEN linux_password_hash ELSE '' END WHERE id=$1", id, status)
		if err != nil {
			return err
		}
		if status != "active" {
			if _, err = tx.Exec(ctx, "UPDATE ssh_keys SET status='revoked' WHERE user_id=$1 AND status='active'", id); err != nil {
				return err
			}
			if _, err = tx.Exec(ctx, "UPDATE api_tokens SET revoked_at=now() WHERE user_id=$1 AND revoked_at IS NULL", id); err != nil {
				return err
			}
			if _, err = tx.Exec(ctx, "UPDATE notification_channels SET enabled=false WHERE user_id=$1", id); err != nil {
				return err
			}
		}
		return requireAdministrator(ctx, tx)
	})
}
func (s *Store) AcceptInvite(ctx context.Context, token, hash string) (identity.User, error) {
	var u identity.User
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return u, err
	}
	defer tx.Rollback(ctx)
	var id string
	err = tx.QueryRow(ctx, "UPDATE invitations SET used_at=now() WHERE hash=$1 AND used_at IS NULL AND expires_at>now() RETURNING user_id", security.HashToken(token)).Scan(&id)
	if err != nil {
		return u, ErrForbidden
	}
	_, err = tx.Exec(ctx, "UPDATE users SET password_hash=$2,status='active',auth_version=auth_version+1 WHERE id=$1 AND status='invited'", id, hash)
	if err != nil {
		return u, err
	}
	var rev int64
	err = tx.QueryRow(ctx, "UPDATE system_state SET revision=revision+1 RETURNING revision").Scan(&rev)
	if err != nil {
		return u, err
	}
	_, err = s.record(ctx, tx, authorization.Principal{UserID: id}, change{Kind: "user.activate", Resource: id, UserID: id}, rev)
	if err != nil {
		return u, err
	}
	return s.User(ctx, id)
}
func (s *Store) SetLinuxPassword(ctx context.Context, p authorization.Principal, id, hash string) (string, error) {
	permission := ""
	if p.UserID != id {
		permission = "users.manage"
	}
	return s.mutate(ctx, p, change{Kind: "user.password", Resource: id, Permission: permission, Group: "*", UserID: id}, func(tx pgx.Tx) error {
		if hash != "" {
			var allowed bool
			if err := tx.QueryRow(ctx, `SELECT u.sync_to_nodes AND EXISTS(SELECT 1 FROM native_role_bindings b JOIN roles r ON r.id=b.role_id WHERE b.user_id=u.id AND r.linux_access AND r.allow_password) FROM users u WHERE u.id=$1 AND u.status='active' FOR UPDATE`, id).Scan(&allowed); err != nil {
				return failure(err)
			}
			if !allowed {
				return fmt.Errorf("%w: парольный вход на ноды не разрешён назначенными UNIX-ролями или синхронизация пользователя выключена", ErrForbidden)
			}
		}
		tag, err := tx.Exec(ctx, "UPDATE users SET linux_password_hash=$2 WHERE id=$1 AND status='active'", id, hash)
		if err == nil && tag.RowsAffected() != 1 {
			return ErrNotFound
		}
		return err
	})
}
func (s *Store) Keys(ctx context.Context, p authorization.Principal, id string) ([]credentials.Key, error) {
	if !p.Self(id) && !p.Allowed("users.read", "*") {
		return nil, ErrForbidden
	}
	rows, err := s.Pool.Query(ctx, "SELECT id,user_id,name,public_key,fingerprint,algorithm,status,expires_at,created_at FROM ssh_keys WHERE user_id=$1 ORDER BY created_at DESC", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	keys := []credentials.Key{}
	for rows.Next() {
		var k credentials.Key
		if err = rows.Scan(&k.ID, &k.UserID, &k.Name, &k.PublicKey, &k.Fingerprint, &k.Algorithm, &k.Status, &k.ExpiresAt, &k.CreatedAt); err != nil {
			return nil, err
		}
		if k.Status == "active" && !k.ExpiresAt.After(time.Now()) {
			k.Status = "expired"
		}
		keys = append(keys, k)
	}
	return keys, rows.Err()
}
func (s *Store) AddKey(ctx context.Context, p authorization.Principal, k credentials.Key) (credentials.Key, string, error) {
	k.ID = uuid.NewString()
	permission := ""
	if p.UserID != k.UserID {
		permission = "users.manage"
	}
	op, err := s.mutate(ctx, p, change{Kind: "key.add", Resource: k.ID, Permission: permission, Group: "*", UserID: k.UserID}, func(tx pgx.Tx) error {
		var raw []byte
		if err := tx.QueryRow(ctx, "SELECT value FROM runtime_settings WHERE id=true").Scan(&raw); err != nil {
			return err
		}
		var policy application.Settings
		if err := json.Unmarshal(raw, &policy); err != nil {
			return err
		}
		var required bool
		if err := tx.QueryRow(ctx, "SELECT sk_required($1)", k.UserID).Scan(&required); err != nil {
			return err
		}

		canonical, fp, algorithm, err := credentials.Parse(k.PublicKey, policy.RequireSK || required)
		if err != nil {
			return err
		}
		k.PublicKey = canonical
		k.Fingerprint = fp
		k.Algorithm = algorithm
		deadline := time.Now().Add(time.Duration(policy.KeyTTLSeconds) * time.Second)
		if k.ExpiresAt.After(deadline) {
			k.ExpiresAt = deadline
		}
		if !k.ExpiresAt.After(time.Now()) {
			return errors.New("key expiry must be in the future")
		}
		var active bool
		if err := tx.QueryRow(ctx, "SELECT status='active' FROM users WHERE id=$1", k.UserID).Scan(&active); err != nil {
			return failure(err)
		}
		if !active {
			return errors.New("user is not active")
		}
		_, err = tx.Exec(ctx, "INSERT INTO ssh_keys(id,user_id,name,public_key,fingerprint,algorithm,status,expires_at) VALUES($1,$2,$3,$4,$5,$6,'active',$7)", k.ID, k.UserID, k.Name, k.PublicKey, k.Fingerprint, k.Algorithm, k.ExpiresAt)
		return err
	})
	k.Status = "active"
	return k, op, err
}
func (s *Store) RevokeKey(ctx context.Context, p authorization.Principal, id string) (string, error) {
	var userID string
	if err := s.Pool.QueryRow(ctx, "SELECT user_id FROM ssh_keys WHERE id=$1", id).Scan(&userID); err != nil {
		return "", failure(err)
	}
	permission := ""
	if userID != p.UserID {
		permission = "users.manage"
	}
	return s.mutate(ctx, p, change{Kind: "key.revoke", Resource: id, Permission: permission, Group: "*", UserID: userID}, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "UPDATE ssh_keys SET status='revoked' WHERE id=$1", id)
		return err
	})
}
func (s *Store) UseTOTP(ctx context.Context, id string, step int64) bool {
	tag, err := s.Pool.Exec(ctx, "UPDATE users SET last_totp_step=$2 WHERE id=$1 AND status='active' AND last_totp_step<$2", id, step)
	return err == nil && tag.RowsAffected() == 1
}
func (s *Store) WebAuthnCredentials(ctx context.Context, id string) ([]json.RawMessage, error) {
	rows, err := s.Pool.Query(ctx, "SELECT credential FROM webauthn_credentials WHERE user_id=$1", id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []json.RawMessage{}
	for rows.Next() {
		var b []byte
		if err = rows.Scan(&b); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}
func (s *Store) SaveWebAuthnCredential(ctx context.Context, userID, id string, credential []byte) error {
	_, err := s.Pool.Exec(ctx, "INSERT INTO webauthn_credentials(id,user_id,credential) SELECT $1,id,$3 FROM users WHERE id=$2 AND status='active' ON CONFLICT(id) DO UPDATE SET credential=excluded.credential,last_used=now() WHERE webauthn_credentials.user_id=excluded.user_id", id, userID, credential)
	return err
}
