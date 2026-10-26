package migrations

import (
	"regexp"
	"strconv"
	"testing"
)

func TestEveryEmbeddedMigrationRunsInVersionOrderAndRecordsItsVersion(t *testing.T) {
	list, err := List()
	if err != nil {
		t.Fatal(err)
	}
	entries, err := Files.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != len(entries) || len(list) == 0 {
		t.Fatal("embedded migration omitted from runner")
	}
	record := regexp.MustCompile(`INSERT\s+INTO\s+schema_migrations\s*\(\s*version\s*\)\s+VALUES\s*\(\s*(\d+)\s*\)`)
	previous := 0
	for _, migration := range list {
		if migration.Version <= previous {
			t.Fatal("migration order is unstable")
		}
		previous = migration.Version
		sql, err := Files.ReadFile(migration.File)
		if err != nil {
			t.Fatal(err)
		}
		matches := record.FindSubmatch(sql)
		if len(matches) != 2 || string(matches[1]) != strconv.Itoa(migration.Version) {
			t.Fatalf("%s records the wrong schema version", migration.File)
		}
	}
}
