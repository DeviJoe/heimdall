package migrations

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type Migration struct {
	Version int
	File    string
}

// Discover the embedded schema files. A new migration must not depend on a
// second hand-maintained registration list in the database adapter.
func List() ([]Migration, error) {
	entries, err := Files.ReadDir(".")
	if err != nil {
		return nil, err
	}
	result := make([]Migration, 0, len(entries))
	seen := map[int]bool{}
	for _, entry := range entries {
		prefix, _, ok := strings.Cut(entry.Name(), "_")
		version, err := strconv.Atoi(prefix)
		if !ok || err != nil || version <= 0 || seen[version] || entry.IsDir() || !strings.HasSuffix(entry.Name(), ".sql") {
			return nil, fmt.Errorf("invalid or duplicate schema migration %s", entry.Name())
		}
		seen[version] = true
		result = append(result, Migration{Version: version, File: entry.Name()})
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Version < result[j].Version })
	return result, nil
}
