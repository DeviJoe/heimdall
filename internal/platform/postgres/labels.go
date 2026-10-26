package postgres

import (
	"Heimdall/internal/application"
	"Heimdall/internal/authorization"
	"Heimdall/internal/synchronization"
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
)

func (s *Store) LabelPolicies(ctx context.Context, p authorization.Principal) ([]application.LabelPolicy, error) {
	if !p.Allowed("security.manage", "*") {
		return nil, ErrForbidden
	}
	rows, err := s.Pool.Query(ctx, "SELECT 'user',user_id,level,categories FROM user_security UNION ALL SELECT 'node_group',group_id,level,categories FROM group_security LIMIT 30000")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []application.LabelPolicy{}
	for rows.Next() {
		var v application.LabelPolicy
		if err = rows.Scan(&v.ResourceType, &v.ResourceID, &v.Label.Level, &v.Label.Categories); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *Store) SaveLabelPolicy(ctx context.Context, p authorization.Principal, v application.LabelPolicy) (string, error) {
	if v.Label.Categories == nil {
		v.Label.Categories = []string{}
	}
	if err := v.Label.Validate(); err != nil {
		return "", err
	}
	table, column := "user_security", "user_id"
	if v.ResourceType == "node_group" {
		table, column = "group_security", "group_id"
	} else if v.ResourceType != "user" {
		return "", errors.New("label resource must be user or node_group")
	}
	return s.mutate(ctx, p, change{Kind: "security.policy", Resource: v.ResourceID, Permission: "security.manage", Group: "*", All: true}, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, "INSERT INTO "+table+"("+column+",level,categories) VALUES($1,$2,$3) ON CONFLICT("+column+") DO UPDATE SET level=excluded.level,categories=excluded.categories", v.ResourceID, v.Label.Level, v.Label.Categories)
		if err != nil {
			return err
		}
		if v.ResourceType == "node_group" {
			var tooMany bool
			err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT c.descendant_id FROM server_group_closure c JOIN group_security s ON s.group_id=c.ancestor_id CROSS JOIN LATERAL unnest(s.categories) tag GROUP BY c.descendant_id HAVING count(DISTINCT tag)>64)`).Scan(&tooMany)
			if err != nil {
				return err
			}
			if tooMany {
				return errors.New("inherited node categories exceed 64")
			}
		}
		return nil
	})
}
func (s *Store) projectLabels(ctx context.Context, tx pgx.Tx, state *synchronization.Snapshot, group string, ids []string, indices map[string]int, eligible map[string]bool) error {
	if err := tx.QueryRow(ctx, `SELECT coalesce(max(s.level),0),ARRAY(SELECT DISTINCT tag FROM group_security s JOIN server_group_closure c ON c.ancestor_id=s.group_id CROSS JOIN LATERAL unnest(s.categories) tag WHERE c.descendant_id=$1 ORDER BY tag) FROM group_security s JOIN server_group_closure c ON c.ancestor_id=s.group_id WHERE c.descendant_id=$1`, group).Scan(&state.Label.Level, &state.Label.Categories); err != nil {
		return err
	}
	rows, err := tx.Query(ctx, "SELECT user_id,level,categories FROM user_security WHERE user_id=ANY($1::uuid[])", ids)
	if err != nil {
		return err
	}
	for rows.Next() {
		var id string
		var l authorization.SecurityLabel
		if err = rows.Scan(&id, &l.Level, &l.Categories); err != nil {
			rows.Close()
			return err
		}
		state.Accounts[indices[id]].Clearance = l
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for i := range state.Accounts {
		a := &state.Accounts[i]
		eligible[a.User.ID] = eligible[a.User.ID] && a.Clearance.Dominates(state.Label)
	}
	return nil
}
