package postgres

import (
	"Heimdall/internal/application"
	"Heimdall/internal/authorization"
	"Heimdall/internal/knowledge"
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"strings"
)

func documentationReader(p authorization.Principal) bool {
	return p.UserID != "" && (p.TokenID == "" || p.Allowed("documentation.read", "*"))
}
func (s *Store) SeedDocumentation(ctx context.Context) error {
	pages, err := knowledge.Defaults()
	if err != nil {
		return err
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	for _, p := range pages {
		// Product instructions follow upgrades until an administrator edits
		// them. Keep every local edit and increment the version on seed changes
		// so an already-open editor cannot overwrite a new instruction.
		if _, err = tx.Exec(ctx, `INSERT INTO documentation_pages(slug,title,markdown) VALUES($1,$2,$3)
 ON CONFLICT(slug) DO UPDATE SET title=excluded.title,markdown=excluded.markdown,version=documentation_pages.version+1,updated_at=now()
 WHERE documentation_pages.updated_by IS NULL AND (documentation_pages.title,documentation_pages.markdown) IS DISTINCT FROM (excluded.title,excluded.markdown)`, p.Slug, p.Title, p.Markdown); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}
func (s *Store) DocumentationPage(ctx context.Context, p authorization.Principal, slug string) (knowledge.Page, error) {
	var out knowledge.Page
	if !documentationReader(p) {
		return out, ErrForbidden
	}
	if !knowledge.ValidSlug(slug) {
		return out, errors.New("Некорректный адрес статьи")
	}
	err := s.Pool.QueryRow(ctx, "SELECT slug,title,markdown,version,updated_at,coalesce(updated_by::text,'') FROM documentation_pages WHERE slug=$1", slug).Scan(&out.Slug, &out.Title, &out.Markdown, &out.Version, &out.UpdatedAt, &out.UpdatedBy)
	return out, failureIf(err)
}
func (s *Store) DocumentationPages(ctx context.Context, p authorization.Principal, limit int, after, query string) ([]knowledge.Page, string, error) {
	if !documentationReader(p) {
		return nil, "", ErrForbidden
	}
	if after != "" && !knowledge.ValidSlug(after) {
		return nil, "", errors.New("Некорректный курсор")
	}
	if len(query) > 256 {
		return nil, "", errors.New("Поисковая строка слишком длинная")
	}
	if limit < 1 || limit > 100 {
		limit = 100
	}
	rows, err := s.Pool.Query(ctx, `SELECT slug,title,version,updated_at FROM documentation_pages WHERE ($1='' OR slug>$1) AND ($2='' OR lower(title||' '||slug) LIKE $2) ORDER BY slug LIMIT $3`, after, searchPattern(strings.TrimSpace(query)), limit+1)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	out := []knowledge.Page{}
	for rows.Next() {
		var d knowledge.Page
		if err = rows.Scan(&d.Slug, &d.Title, &d.Version, &d.UpdatedAt); err != nil {
			return nil, "", err
		}
		out = append(out, d)
	}
	if err = rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(out) > limit {
		out = out[:limit]
		next = out[len(out)-1].Slug
	}
	return out, next, nil
}
func (s *Store) SaveDocumentation(ctx context.Context, p authorization.Principal, d knowledge.Page) (string, error) {
	if err := d.Validate(); err != nil {
		return "", err
	}
	return s.mutate(ctx, p, change{Kind: "documentation.update", Resource: d.Slug, Permission: "documentation.manage", Group: "*", TransportOnly: true}, func(tx pgx.Tx) error {
		var affected int64
		if d.Version == 0 {
			tag, err := tx.Exec(ctx, "INSERT INTO documentation_pages(slug,title,markdown,updated_by) VALUES($1,$2,$3,$4) ON CONFLICT(slug) DO NOTHING", d.Slug, d.Title, d.Markdown, p.UserID)
			if err != nil {
				return err
			}
			affected = tag.RowsAffected()
		} else {
			tag, err := tx.Exec(ctx, "UPDATE documentation_pages SET title=$2,markdown=$3,version=version+1,updated_at=now(),updated_by=$4 WHERE slug=$1 AND version=$5", d.Slug, d.Title, d.Markdown, p.UserID, d.Version)
			if err != nil {
				return err
			}
			affected = tag.RowsAffected()
		}
		if affected != 1 {
			return application.ErrConflict
		}
		return nil
	})
}
