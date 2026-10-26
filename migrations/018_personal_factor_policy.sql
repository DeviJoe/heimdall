ALTER TABLE users ADD COLUMN personal_factor_policy text NOT NULL DEFAULT 'none'
 CHECK(personal_factor_policy IN ('none','any','totp','passkey','both'));

-- Every requirement must pass, including the administrator's minimum.
CREATE OR REPLACE FUNCTION mfa_satisfied(subject uuid) RETURNS bool LANGUAGE sql STABLE AS $$
 SELECT u.kind='service' OR NOT EXISTS (
  SELECT 1 FROM (
    SELECT CASE WHEN u.require_mfa AND u.mfa_policy='none' THEN 'any' ELSE u.mfa_policy END policy
    UNION ALL SELECT g.mfa_policy FROM user_group_members m JOIN user_groups g ON g.id=m.group_id WHERE m.user_id=u.id
    UNION ALL SELECT u.personal_factor_policy
  ) policies WHERE CASE policy
    WHEN 'none' THEN false
    WHEN 'any' THEN NOT (u.totp_secret<>'' OR EXISTS(SELECT 1 FROM webauthn_credentials w WHERE w.user_id=u.id))
    WHEN 'totp' THEN u.totp_secret=''
    WHEN 'passkey' THEN NOT EXISTS(SELECT 1 FROM webauthn_credentials w WHERE w.user_id=u.id)
    WHEN 'both' THEN u.totp_secret='' OR NOT EXISTS(SELECT 1 FROM webauthn_credentials w WHERE w.user_id=u.id)
    ELSE true
  END
 ) FROM users u WHERE u.id=subject
$$;
INSERT INTO schema_migrations(version) VALUES(18);
