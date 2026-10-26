ALTER TABLE webauthn_credentials ADD COLUMN name text NOT NULL DEFAULT 'Passkey';
-- Historical credentials do not have a known registration timestamp.
ALTER TABLE webauthn_credentials ADD COLUMN created_at timestamptz;
ALTER TABLE webauthn_credentials ALTER COLUMN created_at SET DEFAULT now();
ALTER TABLE webauthn_credentials ADD COLUMN last_used timestamptz;
ALTER TABLE user_groups ADD COLUMN purpose text NOT NULL DEFAULT 'general' CHECK(purpose IN ('general','factor_policy'));
INSERT INTO user_groups(id,name,mfa_policy,purpose) VALUES
 (gen_random_uuid(),'Факторы: опционально','none','factor_policy'),
 (gen_random_uuid(),'Факторы: TOTP','totp','factor_policy'),
 (gen_random_uuid(),'Факторы: Passkey','passkey','factor_policy'),
 (gen_random_uuid(),'Факторы: TOTP + Passkey','both','factor_policy') ON CONFLICT(name) DO NOTHING;
INSERT INTO schema_migrations(version) VALUES(13);
