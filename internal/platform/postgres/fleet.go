package postgres

import (
	"Heimdall/internal/authorization"
	"Heimdall/internal/credentials"
	"Heimdall/internal/fleet"
	"Heimdall/internal/identity"
	"Heimdall/internal/platform/security"
	"Heimdall/internal/synchronization"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"strings"
	"time"
)

func (s *Store) Nodes(ctx context.Context, p authorization.Principal, offline time.Duration) ([]fleet.Node, error) {
	rows, err := s.Pool.Query(ctx, "SELECT n.id,n.name,n.group_id,g.name,n.desired_revision,n.applied_revision,n.status,n.error,n.last_seen,n.last_progress,n.pending_since,n.cert_expires,n.disabled FROM nodes n JOIN server_groups g ON g.id=n.group_id ORDER BY n.name LIMIT 1000")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []fleet.Node{}
	for rows.Next() {
		var n fleet.Node
		if err = rows.Scan(&n.ID, &n.Name, &n.GroupID, &n.GroupName, &n.DesiredRevision, &n.AppliedRevision, &n.Status, &n.Error, &n.LastSeen, &n.LastProgress, &n.PendingSince, &n.CertExpires, &n.Disabled); err != nil {
			return nil, err
		}
		if !p.Allowed("nodes.read", n.GroupID) {
			continue
		}
		n.Connectivity = "offline"
		if n.LastSeen != nil {
			age := time.Since(*n.LastSeen)
			if age < offline/2 {
				n.Connectivity = "online"
			} else if age < offline {
				n.Connectivity = "suspect"
			}
		}
		out = append(out, n)
	}
	return out, rows.Err()
}
func (s *Store) CreateJoinToken(ctx context.Context, p authorization.Principal, groupID string, maxUses int, ttl time.Duration) (string, error) {
	return s.CreateNamedJoinToken(ctx, p, groupID, "", maxUses, ttl)
}
func (s *Store) CreateNamedJoinToken(ctx context.Context, p authorization.Principal, groupID, name string, maxUses int, ttl time.Duration) (string, error) {
	if len(name) > 120 || strings.ContainsAny(name, "\n\r\x00") {
		return "", errors.New("invalid join token name")
	}
	if maxUses < 0 || maxUses > 1000000000 || ttl < time.Minute || ttl > 3650*24*time.Hour {
		return "", errors.New("join token: uses 0 (unlimited)–1000000000; TTL 1 minute–3650 days")
	}
	token := security.Random(32)
	_, err := s.mutate(ctx, p, change{Kind: "join_token.create", Resource: groupID, Permission: "nodes.manage", Group: groupID, TransportOnly: true}, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "INSERT INTO join_tokens(id,hash,group_id,expires_at,max_uses,name) VALUES($1,$2,$3,$4,$5,$6)", uuid.NewString(), security.HashToken(token), groupID, time.Now().Add(ttl), maxUses, strings.TrimSpace(name))
		return err
	})
	return token, err
}
func (s *Store) Enroll(ctx context.Context, token, name, serial string, expires time.Time, nodeID string) (string, error) {
	return s.enroll(ctx, token, name, serial, expires, nodeID, "")
}
func (s *Store) EnrollBound(ctx context.Context, token, name, serial string, expires time.Time, nodeID, nonce string) (string, error) {
	raw, err := hex.DecodeString(nonce)
	if err != nil || len(raw) != 32 {
		return "", errors.New("invalid root enrollment nonce")
	}
	return s.enroll(ctx, token, name, serial, expires, nodeID, nonce)
}
func (s *Store) enroll(ctx context.Context, token, name, serial string, expires time.Time, nodeID, nonce string) (string, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	var rev int64
	if err = tx.QueryRow(ctx, "UPDATE system_state SET revision=revision+1 RETURNING revision").Scan(&rev); err != nil {
		return "", err
	}
	var groupID string
	err = tx.QueryRow(ctx, "UPDATE join_tokens SET uses=uses+1 WHERE hash=$1 AND (max_uses=0 OR uses<max_uses) AND expires_at>now() AND revoked_at IS NULL RETURNING group_id", security.HashToken(token)).Scan(&groupID)
	if err != nil {
		return "", ErrForbidden
	}
	if _, err = tx.Exec(ctx, "INSERT INTO nodes(id,name,group_id,desired_revision,cert_serial,cert_expires,bootstrap_nonce,bootstrap_token_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8)", nodeID, name, groupID, rev, serial, expires, nonce, security.HashToken(token)); err != nil {
		return "", err
	}
	_, err = s.record(ctx, tx, authorization.Principal{UserID: "agent:" + nodeID}, change{Kind: "node.join", Resource: nodeID, Group: groupID, NodeID: nodeID}, rev)
	return nodeID, err
}
func (s *Store) ConnectNode(ctx context.Context, id, serial string) (int64, error) {
	var generation int64
	err := s.Pool.QueryRow(ctx, "UPDATE nodes SET generation=generation+1,last_seen=now(),certificate_policy_version=CASE WHEN cert_serial=$2 THEN issued_certificate_policy_version ELSE certificate_policy_version END WHERE id=$1 AND ((cert_serial=$2 AND cert_expires>now()) OR (previous_cert_serial=$2 AND previous_cert_expires>now())) AND NOT disabled RETURNING generation", id, serial).Scan(&generation)
	if err != nil {
		return 0, ErrForbidden
	}
	return generation, nil
}
func (s *Store) CertificatePolicy(ctx context.Context) (synchronization.CertificatePolicy, error) {
	var policy synchronization.CertificatePolicy
	err := s.Pool.QueryRow(ctx, "SELECT certificate_policy_version,coalesce((value->>'node_certificate_ttl_seconds')::int,315360000) FROM runtime_settings WHERE id=true").Scan(&policy.Version, &policy.TTLSeconds)
	return policy, err
}
func (s *Store) NodeCertificate(ctx context.Context, id, serial, newSerial string, expires time.Time, policyVersion int64) error {
	tag, err := s.Pool.Exec(ctx, `UPDATE nodes SET previous_cert_serial=$2,
 previous_cert_expires=least(CASE WHEN cert_serial=$2 THEN cert_expires ELSE previous_cert_expires END,now()+interval '15 minutes'),
 cert_serial=$3,cert_expires=$4,issued_certificate_policy_version=$5 WHERE id=$1 AND NOT disabled
 AND $5=(SELECT certificate_policy_version FROM runtime_settings WHERE id=true)
 AND ((cert_serial=$2 AND cert_expires>now()) OR (previous_cert_serial=$2 AND previous_cert_expires>now()))`, id, serial, newSerial, expires, policyVersion)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrForbidden
	}
	return nil
}
func (s *Store) TouchNodes(ctx context.Context, ids []synchronization.AgentHealth) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := s.Pool.Exec(ctx, "UPDATE nodes n SET last_seen=now(),hostname=CASE WHEN h.hostname<>'' THEN h.hostname ELSE n.hostname END,addresses=CASE WHEN h.hostname<>'' THEN coalesce(h.addresses,'{}') ELSE n.addresses END,platform=CASE WHEN h.hostname<>'' THEN h.platform ELSE n.platform END,metadata_seen=CASE WHEN h.hostname<>'' THEN now() ELSE n.metadata_seen END,local_error=h.error,last_local_check=CASE WHEN h.checked_at>'2000-01-01' THEN h.checked_at ELSE n.last_local_check END,status=CASE WHEN desired_revision=applied_revision THEN CASE WHEN h.error<>'' THEN 'failed' ELSE 'in_sync' END ELSE status END,error=CASE WHEN desired_revision=applied_revision THEN h.error ELSE n.error END FROM jsonb_to_recordset($1) AS h(node_id uuid,error text,checked_at timestamptz,hostname text,addresses text[],platform text) WHERE n.id=h.node_id AND NOT disabled", jsonValue(ids))
	return err
}
func (s *Store) NodeAllowed(ctx context.Context, id, serial string) bool {
	var ok bool
	err := s.Pool.QueryRow(ctx, "SELECT NOT disabled AND ((cert_serial=$2 AND cert_expires>now()) OR (previous_cert_serial=$2 AND previous_cert_expires>now())) FROM nodes WHERE id=$1", id, serial).Scan(&ok)
	return err == nil && ok
}
func (s *Store) PendingNodes(ctx context.Context) ([]string, error) {
	rows, err := s.Pool.Query(ctx, "SELECT id FROM nodes WHERE desired_revision>applied_revision AND NOT disabled ORDER BY pending_since LIMIT 20000")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
func (s *Store) RetryNode(ctx context.Context, p authorization.Principal, id string) (string, error) {
	var groupID string
	if err := s.Pool.QueryRow(ctx, "SELECT group_id FROM nodes WHERE id=$1", id).Scan(&groupID); err != nil {
		return "", failure(err)
	}
	return s.mutate(ctx, p, change{Kind: "node.resync", Resource: id, Permission: "sync.retry", Group: groupID, NodeID: id}, func(tx pgx.Tx) error { return nil })
}
func (s *Store) SetNode(ctx context.Context, p authorization.Principal, id, groupID string, disabled bool) (string, error) {
	var oldGroup string
	if err := s.Pool.QueryRow(ctx, "SELECT group_id FROM nodes WHERE id=$1", id).Scan(&oldGroup); err != nil {
		return "", failure(err)
	}
	if !p.Allowed("nodes.manage", groupID) {
		return "", ErrForbidden
	}
	return s.mutate(ctx, p, change{Kind: "node.update", Resource: id, Permission: "nodes.manage", Group: oldGroup, NodeID: id, TransportOnly: disabled && groupID == oldGroup}, func(tx pgx.Tx) error {
		current, err := s.principal(ctx, tx, p.UserID, p.TokenID, p.Audience)
		if err != nil {
			return err
		}
		var actualGroup string
		if err = tx.QueryRow(ctx, "SELECT group_id FROM nodes WHERE id=$1 FOR UPDATE", id).Scan(&actualGroup); err != nil {
			return failure(err)
		}
		if actualGroup != oldGroup {
			return errors.New("node group changed; reload and retry")
		}
		if !current.Allowed("nodes.manage", groupID) || !current.Allowed("nodes.manage", actualGroup) {
			return ErrForbidden
		}
		_, err = tx.Exec(ctx, "UPDATE nodes SET group_id=$2,disabled=$3 WHERE id=$1", id, groupID, disabled)
		return err
	})
}

func (s *Store) Snapshot(ctx context.Context, id string) (synchronization.Snapshot, error) {
	return s.SnapshotForAgent(ctx, id, -1)
}
func (s *Store) SnapshotForAgent(ctx context.Context, id string, agentRevision int64) (synchronization.Snapshot, error) {
	var state synchronization.Snapshot
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return state, err
	}
	defer tx.Rollback(ctx)
	var groupID string
	var disabled bool
	err = tx.QueryRow(ctx, "SELECT n.group_id,n.desired_revision,n.applied_revision,n.disabled,s.epoch,n.bootstrap_nonce,n.bootstrap_token_hash FROM nodes n CROSS JOIN system_state s WHERE n.id=$1", id).Scan(&groupID, &state.Revision, &state.BaseRevision, &disabled, &state.Epoch, &state.BootstrapNonce, &state.BootstrapTokenHash)
	if err != nil {
		return state, err
	}
	if disabled {
		return state, ErrForbidden
	}
	state.NodeID = id
	state.Schema = 3
	state.IssuedAt = time.Now().UTC()
	if err = tx.QueryRow(ctx, "SELECT certificate_policy_version,coalesce((value->>'node_certificate_ttl_seconds')::int,315360000) FROM runtime_settings WHERE id=true").Scan(&state.CertificatePolicy.Version, &state.CertificatePolicy.TTLSeconds); err != nil {
		return state, err
	}
	state.Accounts = []synchronization.Account{}
	state.Full = state.BaseRevision == 0 || (agentRevision >= 0 && agentRevision != state.BaseRevision)
	if !state.Full {
		if err = tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM sync_targets t JOIN sync_operations o ON o.id=t.operation_id WHERE t.node_id=$1 AND t.revision>$2 AND o.user_id IS NULL)", id, state.BaseRevision).Scan(&state.Full); err != nil {
			return state, err
		}
	}
	rows, err := tx.Query(ctx, "SELECT "+userColumns+",linux_password_hash,mfa_satisfied(id) FROM users WHERE (id IN (SELECT user_id FROM node_accounts WHERE node_id=$1) OR (sync_to_nodes AND id IN (SELECT b.user_id FROM native_role_bindings b JOIN roles r ON r.id=b.role_id WHERE r.linux_access AND (b.group_id=$2 OR b.group_id='*')))) AND ($3 OR id IN (SELECT o.user_id FROM sync_targets t JOIN sync_operations o ON o.id=t.operation_id WHERE t.node_id=$1 AND t.revision>$4)) ORDER BY login LIMIT 20001", id, groupID, state.Full, state.BaseRevision)
	if err != nil {
		return state, err
	}
	eligible := map[string]bool{}
	indices := map[string]int{}
	ids := []string{}
	for rows.Next() {
		var a synchronization.Account
		var u identity.User
		var permitted bool
		err = rows.Scan(&u.ID, &u.Login, &u.DisplayName, &u.Status, &u.UID, &u.GID, &u.Home, &u.Shell, &u.GECOS, &u.RequireMFA, &u.MFAEnabled, &u.AuthVersion, &u.Source, &u.CreatedAt, &u.Kind, &u.MFAPolicy, &u.RequireSK, &u.TOTPEnabled, &u.PasskeyCount, &u.SyncToNodes, &a.PasswordHash, &permitted)
		if err != nil {
			rows.Close()
			return state, err
		}
		a.User = u
		a.Keys = []credentials.Key{}
		a.Sudo = []authorization.SudoRule{}
		eligible[u.ID] = permitted
		indices[u.ID] = len(state.Accounts)
		ids = append(ids, u.ID)
		state.Accounts = append(state.Accounts, a)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return state, err
	}
	if err = s.projectLabels(ctx, tx, &state, groupID, ids, indices, eligible); err != nil {
		return state, err
	}
	if len(ids) > 0 {
		if len(ids) > 20000 {
			return state, errors.New("node account manifest exceeds supported limit")
		}
		rows, err = tx.Query(ctx, "SELECT b.user_id,r.sudo,r.sudoers,r.allow_password,r.allow_ssh_keys FROM native_role_bindings b JOIN roles r ON r.id=b.role_id WHERE r.linux_access AND b.user_id=ANY($1::uuid[]) AND (b.group_id=$2 OR b.group_id='*')", ids, groupID)
		if err != nil {
			return state, err
		}
		for rows.Next() {
			var userID string
			var rules []byte
			var nativeRules string
			var password, keys bool
			if err = rows.Scan(&userID, &rules, &nativeRules, &password, &keys); err != nil {
				rows.Close()
				return state, err
			}
			i := indices[userID]
			a := &state.Accounts[i]
			a.AllowPassword = a.AllowPassword || password
			a.AllowSSHKeys = a.AllowSSHKeys || keys
			a.Enabled = a.User.Active() && a.User.SyncToNodes && eligible[userID]
			var sudo []authorization.SudoRule
			json.Unmarshal(rules, &sudo)
			if a.Enabled {
				a.Sudo = append(a.Sudo, sudo...)
				if nativeRules != "" {
					a.Sudoers = append(a.Sudoers, nativeRules)
				}
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return state, err
		}
		for i := range state.Accounts {
			a := &state.Accounts[i]
			a.Enabled = a.Enabled && (a.AllowPassword || a.AllowSSHKeys)
		}
		rows, err = tx.Query(ctx, "SELECT id,user_id,name,public_key,fingerprint,algorithm,status,expires_at,created_at FROM ssh_keys WHERE user_id=ANY($1::uuid[]) AND status='active' AND expires_at>now() ORDER BY fingerprint", ids)
		if err != nil {
			return state, err
		}
		for rows.Next() {
			var k credentials.Key
			if err = rows.Scan(&k.ID, &k.UserID, &k.Name, &k.PublicKey, &k.Fingerprint, &k.Algorithm, &k.Status, &k.ExpiresAt, &k.CreatedAt); err != nil {
				rows.Close()
				return state, err
			}
			a := &state.Accounts[indices[k.UserID]]
			if a.Enabled && a.AllowSSHKeys {
				a.Keys = append(a.Keys, k)
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return state, err
		}
		if _, err = tx.Exec(ctx, "INSERT INTO node_accounts(node_id,user_id,revision) SELECT $1,id,$2 FROM unnest($3::uuid[]) id ON CONFLICT(node_id,user_id) DO NOTHING", id, state.Revision, ids); err != nil {
			return state, err
		}
	}
	if err = s.projectUnixGroups(ctx, tx, &state, ids, indices); err != nil {
		return state, err
	}
	for i := range state.Accounts {
		if !state.Accounts[i].AllowPassword {
			state.Accounts[i].PasswordHash = ""
		}
		if !state.Accounts[i].Enabled {
			state.Accounts[i].AllowPassword = false
			state.Accounts[i].AllowSSHKeys = false
			state.Accounts[i].PasswordHash = ""
			state.Accounts[i].Keys = []credentials.Key{}
			state.Accounts[i].Sudo = []authorization.SudoRule{}
			state.Accounts[i].Sudoers = nil
		}
	}
	return state, tx.Commit(ctx)
}
func (s *Store) ApplyResult(ctx context.Context, id string, generation int64, r synchronization.ApplyResult) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	var desired, applied, currentGeneration int64
	if err = tx.QueryRow(ctx, "SELECT desired_revision,applied_revision,generation FROM nodes WHERE id=$1 AND NOT disabled FOR UPDATE", id).Scan(&desired, &applied, &currentGeneration); err != nil {
		return err
	}
	if generation != currentGeneration || r.Revision > desired || r.Revision < applied {
		return errors.New("stale or invalid apply result")
	}
	for _, result := range r.Results {
		tag, err := tx.Exec(ctx, "INSERT INTO sync_resources(node_id,user_id,revision,status,error) SELECT $1,user_id,$3,$4,$5 FROM node_accounts WHERE node_id=$1 AND user_id=$2 ON CONFLICT(node_id,user_id) DO UPDATE SET revision=excluded.revision,status=excluded.status,error=excluded.error,updated_at=now() WHERE sync_resources.revision<=excluded.revision", id, result.UserID, r.Revision, result.Status, result.Error)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return errors.New("unknown apply resource")
		}
	}
	status := "pending"
	if r.Error != "" {
		status = "failed"
		_, err = tx.Exec(ctx, "UPDATE sync_targets SET status='failed',error=$3,updated_at=now() WHERE node_id=$1 AND revision<=$2 AND status<>'applied'", id, r.Revision, r.Error)
	} else {
		if desired == r.Revision {
			status = "in_sync"
		}
		_, err = tx.Exec(ctx, "UPDATE sync_targets SET status='applied',error='',updated_at=now() WHERE node_id=$1 AND revision<=$2", id, r.Revision)
	}
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, "UPDATE nodes SET applied_revision=CASE WHEN $4='' THEN $2 ELSE applied_revision END,digest=CASE WHEN $4='' THEN $3 ELSE digest END,status=$5,error=$4,last_seen=now(),last_progress=CASE WHEN $4='' AND applied_revision<$2 THEN now() ELSE last_progress END WHERE id=$1", id, r.Revision, r.Digest, r.Error, status)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
