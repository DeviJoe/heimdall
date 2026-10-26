package postgres

import (
	"Heimdall/internal/application"
	"Heimdall/internal/authorization"
	"Heimdall/internal/platform/security"
	"Heimdall/internal/synchronization"
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"time"
)

func (s *Store) Operations(ctx context.Context, p authorization.Principal) ([]synchronization.Operation, error) {
	groups, err := s.allowedGroups(ctx, p, "sync.read")
	if err != nil {
		return nil, err
	}
	rows, err := s.Pool.Query(ctx, "SELECT o.id,o.kind,o.resource_id,o.revision,o.created_at,count(t.node_id),count(t.node_id) FILTER(WHERE t.status='applied'),count(t.node_id) FILTER(WHERE t.status='failed') FROM sync_operations o LEFT JOIN sync_targets t ON t.operation_id=o.id LEFT JOIN nodes n ON n.id=t.node_id WHERE $1 OR n.group_id=ANY($2::uuid[]) OR ($4 AND o.user_id::text=$3) GROUP BY o.id ORDER BY o.revision DESC LIMIT 200", groups == nil, groups, p.UserID, p.Self(p.UserID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []synchronization.Operation{}
	for rows.Next() {
		var o synchronization.Operation
		if err = rows.Scan(&o.ID, &o.Kind, &o.ResourceID, &o.Revision, &o.CreatedAt, &o.Total, &o.Applied, &o.Failed); err != nil {
			return nil, err
		}
		o.Status = "pending"
		if o.Applied == o.Total {
			o.Status = "succeeded"
		} else if o.Failed > 0 {
			o.Status = "failed"
		}
		out = append(out, o)
	}
	return out, rows.Err()
}
func (s *Store) OperationTargets(ctx context.Context, p authorization.Principal, id string) ([]map[string]any, error) {
	v, _, err := s.OperationTargetsPage(ctx, p, id, 100, "")
	return v, err
}
func (s *Store) OperationTargetsPage(ctx context.Context, p authorization.Principal, id string, limit int, after string) ([]map[string]any, string, error) {
	if limit < 1 || limit > 500 {
		limit = 100
	}
	if after != "" {
		if _, err := uuid.Parse(after); err != nil {
			return nil, "", fmt.Errorf("invalid cursor")
		}
	}
	groups, err := s.allowedGroups(ctx, p, "sync.read")
	if err != nil {
		return nil, "", err
	}
	rows, err := s.Pool.Query(ctx, "SELECT n.id,n.name,n.group_id,t.status,t.error,t.revision,t.updated_at FROM sync_targets t JOIN nodes n ON n.id=t.node_id WHERE operation_id=$1 AND ($2 OR n.group_id=ANY($3::uuid[])) AND ($4='' OR n.id>NULLIF($4,'')::uuid) ORDER BY n.id LIMIT $5", id, groups == nil, groups, after, limit+1)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var nodeID, name, groupID, status, errorText string
		var rev int64
		var updated time.Time
		if err = rows.Scan(&nodeID, &name, &groupID, &status, &errorText, &rev, &updated); err != nil {
			return nil, "", err
		}
		if p.Allowed("sync.read", groupID) {
			out = append(out, map[string]any{"node_id": nodeID, "name": name, "group_id": groupID, "status": status, "error": errorText, "revision": rev, "updated_at": updated})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		next = out[len(out)-1]["node_id"].(string)
	}
	return out, next, nil
}
func (s *Store) UserSync(ctx context.Context, p authorization.Principal, id string) ([]map[string]any, error) {
	v, _, err := s.UserSyncPage(ctx, p, id, 100, "")
	return v, err
}
func (s *Store) UserSyncPage(ctx context.Context, p authorization.Principal, id string, limit int, after string) ([]map[string]any, string, error) {
	if limit < 1 || limit > 500 {
		limit = 100
	}
	if after != "" {
		if _, err := uuid.Parse(after); err != nil {
			return nil, "", fmt.Errorf("invalid cursor")
		}
	}
	if !p.Self(id) && !p.Allowed("users.read", "*") {
		return nil, "", ErrForbidden
	}
	rows, err := s.Pool.Query(ctx, "SELECT n.id,n.name,n.group_id,n.desired_revision,n.applied_revision,n.last_seen,CASE WHEN n.local_error<>'' THEN 'failed' WHEN EXISTS(SELECT 1 FROM sync_targets t JOIN sync_operations o ON o.id=t.operation_id WHERE t.node_id=n.id AND o.user_id=$1 AND t.status<>'applied') THEN CASE WHEN n.status='failed' THEN 'failed' ELSE 'pending' END ELSE coalesce(r.status,'pending') END,CASE WHEN n.local_error<>'' THEN n.local_error ELSE coalesce(r.error,'') END,r.updated_at FROM nodes n LEFT JOIN sync_resources r ON r.node_id=n.id AND r.user_id=$1 WHERE (n.id IN (SELECT node_id FROM node_accounts WHERE user_id=$1) OR EXISTS(SELECT 1 FROM native_role_bindings b JOIN roles role ON role.id=b.role_id WHERE b.user_id=$1 AND role.linux_access AND (b.group_id=n.group_id::text OR b.group_id='*'))) AND ($2='' OR n.id>NULLIF($2,'')::uuid) ORDER BY n.id LIMIT $3", id, after, limit+1)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var nodeID, name, group, status, errorText string
		var desired, applied int64
		var seen, updated *time.Time
		if err = rows.Scan(&nodeID, &name, &group, &desired, &applied, &seen, &status, &errorText, &updated); err != nil {
			return nil, "", err
		}
		out = append(out, map[string]any{"node_id": nodeID, "name": name, "group_id": group, "desired_revision": desired, "applied_revision": applied, "last_seen": seen, "status": status, "error": errorText, "updated_at": updated})
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		next = out[len(out)-1]["node_id"].(string)
	}
	return out, next, nil
}
func (s *Store) Incidents(ctx context.Context, p authorization.Principal) ([]synchronization.Incident, error) {
	groups, err := s.allowedGroups(ctx, p, "incidents.read")
	if err != nil {
		return nil, err
	}
	rows, err := s.Pool.Query(ctx, "SELECT id,kind,severity,coalesce(node_id::text,''),coalesce(group_id::text,''),coalesce(user_id::text,''),message,status,created_at,occurrences,last_seen FROM incidents WHERE $1 OR group_id=ANY($2::uuid[]) OR ($4 AND user_id::text=$3) ORDER BY (status='resolved'),(severity='critical') DESC,last_seen DESC LIMIT 200", groups == nil, groups, p.UserID, p.Self(p.UserID))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []synchronization.Incident{}
	for rows.Next() {
		var i synchronization.Incident
		if err = rows.Scan(&i.ID, &i.Kind, &i.Severity, &i.NodeID, &i.GroupID, &i.UserID, &i.Message, &i.Status, &i.CreatedAt, &i.Occurrences, &i.LastSeen); err != nil {
			return nil, err
		}
		if p.Allowed("incidents.read", i.GroupID) || p.Allowed("incidents.read", "*") || p.Self(i.UserID) {
			out = append(out, i)
		}
	}
	return out, rows.Err()
}
func (s *Store) Acknowledge(ctx context.Context, p authorization.Principal, id string) error {
	var group string
	if err := s.Pool.QueryRow(ctx, "SELECT coalesce(group_id::text,'*') FROM incidents WHERE id=$1", id).Scan(&group); err != nil {
		return failure(err)
	}
	if !p.Allowed("sync.retry", group) {
		return ErrForbidden
	}
	_, err := s.Pool.Exec(ctx, "UPDATE incidents SET status='acknowledged' WHERE id=$1 AND status='open'", id)
	return err
}
func (s *Store) AuditEvents(ctx context.Context, p authorization.Principal) ([]map[string]any, error) {
	if !p.Allowed("audit.read", "*") {
		return nil, ErrForbidden
	}
	rows, err := s.Pool.Query(ctx, "SELECT id,actor_id,channel,action,resource_id,created_at FROM audit_events ORDER BY id DESC LIMIT 200")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var id int64
		var actor, channel, action, resource string
		var created time.Time
		if err = rows.Scan(&id, &actor, &channel, &action, &resource, &created); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{"id": id, "actor_id": actor, "channel": channel, "action": action, "resource_id": resource, "created_at": created})
	}
	return out, rows.Err()
}

func (s *Store) Detect(ctx context.Context, stalled, offline, revocation time.Duration) error {
	type problem struct{ key, kind, severity, node, group, message string }
	rows, err := s.Pool.Query(ctx, "SELECT n.id,n.group_id,n.name,n.status,n.error,n.pending_since,n.last_seen,EXISTS(SELECT 1 FROM sync_targets t JOIN sync_operations o ON o.id=t.operation_id WHERE t.node_id=n.id AND t.status<>'applied' AND o.kind IN ('user.disabled','user.deleted','user.update','key.revoke','key.expire','key.policy','role.unbind','role.update','mfa.reset','directory.update','user.policy','user_group.update','user_group.role','user_group.unbind','user_group.delete','unix_group.delete','group.delete','unix_group.update','unix_group.bind','unix_group.unbind','security.policy','nodes.move','settings.update')),n.cert_expires<=now(),n.certificate_policy_version<settings.certificate_policy_version FROM nodes n CROSS JOIN runtime_settings settings WHERE n.desired_revision>n.applied_revision OR (NOT disabled AND (n.status='failed' OR last_seen IS NULL OR last_seen<now()-$1::interval OR n.cert_expires<=now() OR n.certificate_policy_version<settings.certificate_policy_version))", fmt.Sprintf("%f seconds", offline.Seconds()))
	if err != nil {
		return err
	}
	problems := []problem{}
	for rows.Next() {
		var id, group, name, status, detail string
		var pending time.Time
		var seen *time.Time
		var revoke, certificateExpired, certificatePending bool
		if err = rows.Scan(&id, &group, &name, &status, &detail, &pending, &seen, &revoke, &certificateExpired, &certificatePending); err != nil {
			rows.Close()
			return err
		}
		kind := ""
		severity := "warning"
		message := ""
		if revoke && time.Since(pending) > revocation {
			kind = "revocation_pending"
			severity = "critical"
			message = "Отзыв доступа не подтверждён на ноде " + name
		} else if status == "failed" {
			kind = "apply_failed"
			severity = "critical"
			message = "Ошибка применения UNIX-настроек на ноде " + name + ": " + detail
		} else if status != "in_sync" && time.Since(pending) > stalled {
			kind = "sync_stalled"
			severity = "critical"
			message = "Синхронизация зависла на ноде " + name
		} else if certificatePending && time.Since(pending) > stalled {
			kind, severity = "sync_stalled", "critical"
			message = "Перевыпуск транспортного сертификата не подтверждён на ноде " + name
		} else if certificateExpired || (seen == nil && time.Since(pending) > offline) || (seen != nil && time.Since(*seen) > offline) {
			kind = "node_offline"
			message = "Агент ноды " + name + " недоступен"
		}
		if certificateExpired {
			severity = "critical"
			message += ". Транспортный сертификат истёк; требуется recovery-токен"
		}
		if kind != "" {
			key := kind + ":" + id
			problems = append(problems, problem{key, kind, severity, id, group, message})
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	payload := make([]map[string]string, 0, len(problems))
	keys := make([]string, 0, len(problems))
	for _, p := range problems {
		payload = append(payload, map[string]string{"id": uuid.NewString(), "dedup_key": p.key, "kind": p.kind, "severity": p.severity, "node_id": p.node, "group_id": p.group, "message": p.message})
		keys = append(keys, p.key)
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	rows, err = tx.Query(ctx, "INSERT INTO incidents(id,dedup_key,kind,severity,node_id,group_id,message) SELECT p.id,p.dedup_key,p.kind,p.severity,p.node_id,p.group_id,p.message FROM jsonb_to_recordset($1) AS p(id uuid,dedup_key text,kind text,severity text,node_id uuid,group_id uuid,message text) ON CONFLICT(dedup_key) DO UPDATE SET status='open',message=excluded.message,updated_at=now(),last_seen=now() WHERE incidents.status='resolved' RETURNING id", data)
	if err != nil {
		return err
	}
	changed := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		changed = append(changed, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	rows, err = tx.Query(ctx, "UPDATE incidents SET status='resolved',updated_at=now() WHERE status<>'resolved' AND node_id IS NOT NULL AND kind IN ('apply_failed','sync_stalled','revocation_pending','node_offline') AND NOT dedup_key=ANY($1::text[]) RETURNING id", keys)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		changed = append(changed, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if len(changed) > 0 {
		if _, err = tx.Exec(ctx, "INSERT INTO notification_jobs(id,incident_id,channel_id,provider,event) SELECT gen_random_uuid(),i.id,c.id,c.provider,$2 FROM incidents i JOIN notification_channels c ON c.enabled JOIN users u ON u.id=c.user_id AND u.status='active' WHERE i.id=ANY($1::uuid[]) AND mfa_satisfied(u.id) AND (i.user_id=u.id OR EXISTS(SELECT 1 FROM effective_role_bindings b JOIN roles r ON r.id=b.role_id WHERE b.user_id=u.id AND (b.group_id='*' OR b.group_id=i.group_id::text) AND (r.permissions @> '[\"incidents.read\"]' OR r.permissions @> '[\"*\"]'))) ON CONFLICT DO NOTHING", changed, "incident:"+security.Random(8)); err != nil {
			return err
		}
	}

	if _, err = tx.Exec(ctx, `WITH expired AS (DELETE FROM join_tokens WHERE id IN(SELECT id FROM join_tokens WHERE expires_at<=now() ORDER BY expires_at LIMIT 1000 FOR UPDATE SKIP LOCKED) RETURNING id,name)
    INSERT INTO audit_events(actor_id,channel,action,resource_id) SELECT 'system','system','join_token.expired',coalesce(nullif(name,''),'join-token')||':'||id::text FROM expired`); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `WITH expired AS (UPDATE api_tokens SET revoked_at=now() WHERE id IN(SELECT id FROM api_tokens WHERE expires_at<=now() AND revoked_at IS NULL ORDER BY expires_at LIMIT 1000 FOR UPDATE SKIP LOCKED) RETURNING id,name)
    INSERT INTO audit_events(actor_id,channel,action,resource_id) SELECT 'system','system','api_token.expired',name||':'||id::text FROM expired`); err != nil {
		return err
	}
	if err = s.keyExpiryNotices(ctx, tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (s *Store) scheduleNotifications(ctx context.Context, tx pgx.Tx, incident, event string) error {
	_, err := tx.Exec(ctx, "INSERT INTO notification_jobs(id,incident_id,channel_id,provider,event) SELECT gen_random_uuid(),$1,id,provider,$2 FROM notification_channels WHERE enabled ON CONFLICT DO NOTHING", incident, event)
	return err
}

type MetricState = application.MetricState

func (s *Store) Metrics(ctx context.Context) (MetricState, error) {
	m := MetricState{Connectivity: map[string]int{"online": 0, "suspect": 0, "offline": 0, "disabled": 0}, Nodes: map[string]int{}, Directories: map[string]application.DirectoryStatus{}}
	rows, err := s.Pool.Query(ctx, "SELECT status,count(*) FROM nodes GROUP BY status")
	if err != nil {
		return m, err
	}
	for rows.Next() {
		var status string
		var count int
		if err = rows.Scan(&status, &count); err != nil {
			rows.Close()
			return m, err
		}
		m.Nodes[status] = count
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return m, err
	}

	rows, err = s.Pool.Query(ctx, `SELECT CASE WHEN n.disabled THEN 'disabled' WHEN n.last_seen>now()-make_interval(secs=>(settings.value->>'offline_seconds')::int/2) THEN 'online' WHEN coalesce(n.last_seen,n.pending_since)>now()-make_interval(secs=>(settings.value->>'offline_seconds')::int) THEN 'suspect' ELSE 'offline' END,count(*) FROM nodes n CROSS JOIN runtime_settings settings GROUP BY 1`)
	if err != nil {
		return m, err
	}
	for rows.Next() {
		var status string
		var count int
		if err = rows.Scan(&status, &count); err != nil {
			rows.Close()
			return m, err
		}
		m.Connectivity[status] = count
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return m, err
	}
	err = s.Pool.QueryRow(ctx, "SELECT count(*),coalesce(max(extract(epoch FROM now()-pending_since)),0) FROM nodes WHERE desired_revision>applied_revision").Scan(&m.Pending, &m.Oldest)
	if err != nil {
		return m, err
	}
	err = s.Pool.QueryRow(ctx, "SELECT count(*),coalesce(max(extract(epoch FROM now()-n.pending_since)),0) FROM nodes n CROSS JOIN runtime_settings s WHERE NOT n.disabled AND n.certificate_policy_version<s.certificate_policy_version").Scan(&m.CertificatesPending, &m.CertificatesOldest)
	if err != nil {
		return m, err
	}
	err = s.Pool.QueryRow(ctx, "SELECT count(DISTINCT t.node_id) FROM sync_targets t JOIN sync_operations o ON o.id=t.operation_id WHERE t.status<>'applied' AND o.kind IN ('user.disabled','user.deleted','user.update','key.revoke','key.expire','key.policy','role.unbind','role.update','mfa.reset','directory.update','user.policy','user_group.update','user_group.role','user_group.unbind','user_group.delete','unix_group.delete','group.delete','unix_group.update','unix_group.bind','unix_group.unbind','security.policy','nodes.move','settings.update')").Scan(&m.Revocations)
	if err != nil {
		return m, err
	}
	err = s.Pool.QueryRow(ctx, "SELECT coalesce(max(extract(epoch FROM now()-created_at)),0) FROM outbox WHERE processed_at IS NULL").Scan(&m.OutboxOldest)
	if err != nil {
		return m, err
	}
	err = s.Pool.QueryRow(ctx, "SELECT coalesce(max(extract(epoch FROM now()-created_at)),0) FROM notification_jobs WHERE status NOT IN ('accepted_by_provider','cancelled')").Scan(&m.NotificationOldest)
	if err != nil {
		return m, err
	}
	err = s.Pool.QueryRow(ctx, "SELECT count(*) FROM incidents WHERE status<>'resolved'").Scan(&m.Incidents)
	if err != nil {
		return m, err
	}
	rows, err = s.Pool.Query(ctx, "SELECT provider,phase,last_attempt,last_success FROM integration_status")
	if err != nil {
		return m, err
	}
	defer rows.Close()
	for rows.Next() {
		var provider string
		var status application.DirectoryStatus
		if err = rows.Scan(&provider, &status.Phase, &status.LastAttempt, &status.LastSuccess); err != nil {
			return m, err
		}
		m.Directories[provider] = status
	}
	return m, rows.Err()
}
func (s *Store) EnforceKeyPolicy(ctx context.Context, requireSK bool) error {
	rows, err := s.Pool.Query(ctx, "SELECT DISTINCT user_id FROM ssh_keys WHERE status='active' AND (expires_at<=now() OR ($1 AND algorithm NOT LIKE 'sk-%')) LIMIT 100", requireSK)
	if err != nil {
		return err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range ids {
		tx, err := s.Pool.Begin(ctx)
		if err != nil {
			return err
		}
		var rev int64
		err = tx.QueryRow(ctx, "UPDATE system_state SET revision=revision+1 RETURNING revision").Scan(&rev)
		if err == nil {
			_, err = tx.Exec(ctx, "UPDATE ssh_keys SET status=CASE WHEN expires_at<=now() THEN 'expired' ELSE 'revoked' END WHERE user_id=$1 AND status='active' AND (expires_at<=now() OR ($2 AND algorithm NOT LIKE 'sk-%'))", id, requireSK)
		}
		if err == nil {
			_, err = s.record(ctx, tx, authorization.Principal{UserID: "system"}, change{Kind: "key.policy", Resource: id, UserID: id}, rev)
		}
		if err != nil {
			tx.Rollback(ctx)
			return err
		}
	}
	return nil
}
