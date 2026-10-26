//go:build integration

package postgres

import (
	"Heimdall/internal/application"
	"Heimdall/internal/authorization"
	"errors"
	"testing"
)

func TestDocumentationSeedPreservesEditsAndRejectsStaleVersion(t *testing.T) {
	ctx, s, admin, _ := isolatedStore(t)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(s.SeedDocumentation(ctx))
	// Simulate an earlier shipped instruction. An untouched seed may be
	// upgraded repeatedly; local editor changes must stay protected.
	_, err := s.Pool.Exec(ctx, "UPDATE documentation_pages SET markdown='# Earlier shipped instruction' WHERE slug='api-guide' AND updated_by IS NULL")
	must(err)
	oldSeed, err := s.DocumentationPage(ctx, admin, "api-guide")
	must(err)
	must(s.SeedDocumentation(ctx))
	upgraded, err := s.DocumentationPage(ctx, admin, "api-guide")
	must(err)
	if upgraded.Markdown == oldSeed.Markdown || upgraded.Version != oldSeed.Version+1 {
		t.Fatal("untouched product instruction was not upgraded")
	}
	if _, err = s.SaveDocumentation(ctx, admin, oldSeed); !errors.Is(err, application.ErrConflict) {
		t.Fatal("editor overwrote an upgraded instruction")
	}
	must(s.SeedDocumentation(ctx))
	unchanged, err := s.DocumentationPage(ctx, admin, "api-guide")
	must(err)
	if unchanged.Version != upgraded.Version {
		t.Fatal("unchanged seed keeps incrementing versions")
	}
	reader := authorization.Principal{UserID: admin.UserID, Restricted: true}
	page, err := s.DocumentationPage(ctx, reader, "nodes")
	must(err)
	stale := page
	page.Markdown = "# Local instruction\nModified by administrator."
	_, err = s.SaveDocumentation(ctx, admin, page)
	must(err)
	if _, err = s.SaveDocumentation(ctx, admin, stale); !errors.Is(err, application.ErrConflict) {
		t.Fatal("stale version overwrote edit")
	}
	must(s.SeedDocumentation(ctx))
	saved, err := s.DocumentationPage(ctx, reader, "nodes")
	must(err)
	if saved.Markdown != page.Markdown || saved.Version != page.Version+1 {
		t.Fatal("seed replaced editor content")
	}
	if _, err = s.SaveDocumentation(ctx, reader, saved); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("restricted reader edited docs")
	}
	first, next, err := s.DocumentationPages(ctx, reader, 1, "", "")
	must(err)
	if len(first) != 1 || next == "" || first[0].Markdown != "" {
		t.Fatal("list is not paginated metadata")
	}
	reader.TokenID = "denied"
	if _, err = s.DocumentationPage(ctx, reader, "nodes"); !errors.Is(err, application.ErrForbidden) {
		t.Fatal("token bypassed documentation.read")
	}
}
