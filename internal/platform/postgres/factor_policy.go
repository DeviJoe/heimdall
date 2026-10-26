package postgres

import (
	"Heimdall/internal/application"
	"Heimdall/internal/authorization"
	"context"
	"errors"
	"slices"
)

func (s *Store) FactorState(ctx context.Context, id string) (application.FactorState, error) {
	v := application.FactorState{Required: []string{}, AdministratorRequired: []string{}}
	err := s.Pool.QueryRow(ctx, `SELECT totp_secret<>'',EXISTS(SELECT 1 FROM webauthn_credentials WHERE user_id=u.id),personal_factor_policy,coalesce((SELECT array_agg(DISTINCT policy ORDER BY policy) FROM (SELECT CASE WHEN u.require_mfa AND u.mfa_policy='none' THEN 'any' ELSE u.mfa_policy END policy UNION ALL SELECT g.mfa_policy FROM user_groups g JOIN user_group_members m ON m.group_id=g.id WHERE m.user_id=u.id) p WHERE policy<>'none'),'{}') FROM users u WHERE id=$1`, id).Scan(&v.TOTP, &v.Passkey, &v.PersonalPolicy, &v.AdministratorRequired)
	v.Required = append(v.Required, v.AdministratorRequired...)
	if v.PersonalPolicy != "none" && v.PersonalPolicy != "" && !slices.Contains(v.Required, v.PersonalPolicy) {
		v.Required = append(v.Required, v.PersonalPolicy)
	}
	return v, err
}

func (s *Store) SetPersonalFactorPolicy(ctx context.Context, p authorization.Principal, policy string) (string, error) {
	if p.TokenID != "" {
		return "", ErrForbidden
	}
	if !validMFAPolicy(policy) {
		return "", errors.New("Неизвестное требование к факторам")
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	var rev int64
	if err = tx.QueryRow(ctx, "UPDATE system_state SET revision=revision+1 WHERE id=true RETURNING revision").Scan(&rev); err != nil {
		return "", err
	}
	current, err := s.principal(ctx, tx, p.UserID, "", p.Audience)
	if err != nil {
		return "", err
	}
	// Restricted enrollment sessions may change only their own additional
	// requirements. The administrator's and groups' policies are immutable here,
	// so choosing 'none' can never bypass their mandatory enrollment.
	tag, err := tx.Exec(ctx, "UPDATE users SET personal_factor_policy=$2,auth_version=auth_version+1 WHERE id=$1 AND kind='human'", current.UserID, policy)
	if err != nil {
		return "", err
	}
	if tag.RowsAffected() != 1 {
		return "", ErrNotFound
	}
	return s.record(ctx, tx, p, change{Kind: "user.factor_policy", Resource: current.UserID, UserID: current.UserID}, rev)
}
