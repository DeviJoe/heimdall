package knowledge

import (
	"embed"
	"errors"
	"regexp"
	"strings"
	"time"
)

type Page struct {
	Slug      string    `json:"slug"`
	Title     string    `json:"title"`
	Markdown  string    `json:"markdown,omitempty"`
	Version   int64     `json:"version"`
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy string    `json:"updated_by,omitempty"`
}

var slugPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,79}$`)

func ValidSlug(slug string) bool { return slugPattern.MatchString(slug) }
func (p Page) Validate() error {
	if !ValidSlug(p.Slug) || strings.TrimSpace(p.Title) == "" || len(p.Title) > 200 || strings.TrimSpace(p.Markdown) == "" || len(p.Markdown) > 262144 || strings.ContainsRune(p.Markdown, 0) || p.Version < 0 {
		return errors.New("Укажите адрес статьи, заголовок и Markdown (до 256 КиБ)")
	}
	return nil
}

//go:embed content/*.md
var content embed.FS

func Defaults() ([]Page, error) {
	entries, err := content.ReadDir("content")
	if err != nil {
		return nil, err
	}
	pages := []Page{}
	for _, entry := range entries {
		raw, err := content.ReadFile("content/" + entry.Name())
		if err != nil {
			return nil, err
		}
		text := string(raw)
		title, _, _ := strings.Cut(text, "\n")
		p := Page{Slug: strings.TrimSuffix(entry.Name(), ".md"), Title: strings.TrimPrefix(title, "# "), Markdown: text}
		if err = p.Validate(); err != nil {
			return nil, err
		}
		pages = append(pages, p)
	}
	return pages, nil
}
