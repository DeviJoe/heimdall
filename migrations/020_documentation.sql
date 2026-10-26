CREATE TABLE documentation_pages (
 slug text PRIMARY KEY CHECK(slug ~ '^[a-z][a-z0-9-]{0,79}$'),
 title text NOT NULL CHECK(length(title) BETWEEN 1 AND 200),
 markdown text NOT NULL CHECK(octet_length(markdown) BETWEEN 1 AND 262144),
 version bigint NOT NULL DEFAULT 1,
 updated_at timestamptz NOT NULL DEFAULT now(),
 updated_by uuid REFERENCES users(id)
);
CREATE INDEX documentation_title_idx ON documentation_pages(lower(title),slug);
INSERT INTO schema_migrations(version) VALUES(20);
