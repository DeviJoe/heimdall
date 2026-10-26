package postgres

import (
	"Heimdall/internal/authorization"
	"Heimdall/internal/platform/security"
	"context"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"time"
)

// Recovery is deliberately explicit. A short-lived token is bound to the existing
// node identity and cannot enroll another node or reactivate a disabled node.
func (s *Store) CreateRecoveryToken(ctx context.Context, p authorization.Principal, nodeID string) (string, error) {
	var group string
	if err := s.Pool.QueryRow(ctx, "SELECT group_id FROM nodes WHERE id=$1 AND NOT disabled", nodeID).Scan(&group); err != nil {
		return "", failure(err)
	}
	token := security.Random(32)
	_, err := s.mutate(ctx, p, change{Kind: "node.recovery_token", Resource: nodeID, Permission: "nodes.manage", Group: group}, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "UPDATE node_recovery_tokens SET used_at=now() WHERE node_id=$1 AND used_at IS NULL", nodeID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, "INSERT INTO node_recovery_tokens(id,node_id,hash,expires_at) VALUES($1,$2,$3,now()+interval '10 minutes')", uuid.NewString(), nodeID, security.HashToken(token))
		return err
	})
	return token, err
}
func (s *Store) RecoverNode(ctx context.Context, nodeID, token, serial string, expires time.Time) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, "UPDATE node_recovery_tokens SET used_at=now() WHERE node_id=$1 AND hash=$2 AND used_at IS NULL AND expires_at>now()", nodeID, security.HashToken(token))
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrForbidden
	}
	tag, err = tx.Exec(ctx, "UPDATE nodes SET cert_serial=$2,cert_expires=$3,previous_cert_serial='',previous_cert_expires=NULL,certificate_policy_version=0,issued_certificate_policy_version=0,generation=generation+1 WHERE id=$1 AND NOT disabled", nodeID, serial, expires)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrForbidden
	}
	_, err = tx.Exec(ctx, "INSERT INTO audit_events(actor_id,channel,action,resource_id) VALUES($1,'agent','node.recover',$2)", "agent:"+nodeID, nodeID)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
