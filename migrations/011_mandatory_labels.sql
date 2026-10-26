CREATE TABLE user_security(user_id uuid PRIMARY KEY REFERENCES users,level int NOT NULL CHECK(level BETWEEN 0 AND 3),categories text[] NOT NULL DEFAULT '{}');
CREATE TABLE group_security(group_id uuid PRIMARY KEY REFERENCES server_groups,level int NOT NULL CHECK(level BETWEEN 0 AND 3),categories text[] NOT NULL DEFAULT '{}');
CREATE FUNCTION mandatory_allowed(subject uuid,node_group uuid) RETURNS bool LANGUAGE sql STABLE AS $$
 SELECT coalesce((SELECT level FROM user_security WHERE user_id=subject),0)>=coalesce((SELECT max(s.level) FROM group_security s JOIN server_group_closure c ON c.ancestor_id=s.group_id WHERE c.descendant_id=node_group),0)
 AND coalesce((SELECT categories FROM user_security WHERE user_id=subject),'{}'::text[]) @> ARRAY(SELECT DISTINCT category FROM group_security s JOIN server_group_closure c ON c.ancestor_id=s.group_id CROSS JOIN LATERAL unnest(s.categories) category WHERE c.descendant_id=node_group)
$$;
INSERT INTO schema_migrations(version) VALUES(11);
