package knowledge

import (
	"strings"
	"testing"
)

func TestDocumentationHasCompleteValidInitialArticles(t *testing.T) {
	pages, err := Defaults()
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, p := range pages {
		if p.Validate() != nil || have[p.Slug] {
			t.Fatal("invalid or duplicate article")
		}
		have[p.Slug] = true
	}
	for _, slug := range []string{"start", "roles-and-groups", "factors", "ssh-access", "nodes", "synchronization", "automation", "operations"} {
		if !have[slug] {
			t.Fatalf("missing %s", slug)
		}
	}
}
func TestDocumentationRejectsInvalidSlugAndOversizeContent(t *testing.T) {
	for _, slug := range []string{"../etc", "a/b", "<script>", "", "A"} {
		if (Page{Slug: slug, Title: "Title", Markdown: "Content"}).Validate() == nil {
			t.Fatal("unsafe slug")
		}
	}
	if (Page{Slug: "article", Title: "Title", Markdown: strings.Repeat("a", 262145)}).Validate() == nil {
		t.Fatal("oversize article accepted")
	}
}
