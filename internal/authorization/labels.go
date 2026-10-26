package authorization

import (
	"errors"
	"regexp"
)

// Labels constrain host login in addition to RBAC. They do not claim to provide
// kernel MAC for files, processes or information flow after login.
type SecurityLabel struct {
	Level      int      `json:"level"`
	Categories []string `json:"categories"`
}

var categoryPattern = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_.-]{0,63}$`)

func (l SecurityLabel) Validate() error {
	if l.Level < 0 || l.Level > 3 || len(l.Categories) > 64 {
		return errors.New("invalid clearance level or category count")
	}
	seen := map[string]bool{}
	for _, c := range l.Categories {
		if !categoryPattern.MatchString(c) || seen[c] {
			return errors.New("invalid or duplicate security category")
		}
		seen[c] = true
	}
	return nil
}
func (clearance SecurityLabel) Dominates(required SecurityLabel) bool {
	if clearance.Validate() != nil || required.Validate() != nil || clearance.Level < required.Level {
		return false
	}
	categories := map[string]bool{}
	for _, c := range clearance.Categories {
		categories[c] = true
	}
	for _, c := range required.Categories {
		if !categories[c] {
			return false
		}
	}
	return true
}
