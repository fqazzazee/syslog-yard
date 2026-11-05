package store_test

import (
	"context"
	"fmt"
	"io/fs"
	"slices"
	"strings"
	"testing"

	"github.com/syslog-yard/syslog-bucket/internal/store"
	"github.com/syslog-yard/syslog-bucket/internal/store/storetest"
	"github.com/syslog-yard/syslog-bucket/migrations"
)

// schema renders the public schema (columns, constraints, indexes) as text
// so two databases can be compared.
func schema(t *testing.T, st *store.Store) string {
	t.Helper()
	ctx := context.Background()
	var sb strings.Builder
	for _, q := range []string{
		`SELECT table_name, column_name, data_type, is_nullable, COALESCE(column_default, ''), COALESCE(generation_expression, '')
		   FROM information_schema.columns WHERE table_schema = 'public' ORDER BY 1, 2`,
		`SELECT conrelid::regclass::text, conname, pg_get_constraintdef(oid), ''
		   FROM pg_constraint WHERE connamespace = 'public'::regnamespace ORDER BY 1, 2`,
		`SELECT tablename, indexname, indexdef FROM pg_indexes WHERE schemaname = 'public' ORDER BY 1, 2`,
	} {
		rows, err := st.Pool.Query(ctx, q)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			vals, err := rows.Values()
			if err != nil {
				t.Fatal(err)
			}
			fmt.Fprintln(&sb, vals...)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
	}
	return sb.String()
}

func migrationFiles(t *testing.T) []string {
	t.Helper()
	names, err := fs.Glob(migrations.FS, "*.sql")
	if err != nil || len(names) == 0 {
		t.Fatalf("no embedded migrations: %v", err)
	}
	slices.Sort(names)
	return names
}

func appliedMigrations(t *testing.T, st *store.Store) []string {
	t.Helper()
	rows, err := st.Pool.Query(context.Background(), `SELECT filename FROM schema_migrations ORDER BY filename`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		out = append(out, n)
	}
	return out
}

// An empty database migrates to the latest schema, and migrating again is a
// no-op.
func TestMigrateIdempotent(t *testing.T) {
	st := storetest.New(t) // migrated once from empty
	ctx := context.Background()
	files := migrationFiles(t)
	if got := appliedMigrations(t, st); !slices.Equal(got, files) {
		t.Fatalf("applied %v, want %v", got, files)
	}
	before := schema(t, st)
	if !strings.Contains(before, "entries_pkey") || !strings.Contains(before, "bucket_shares") {
		t.Fatalf("schema snapshot looks empty:\n%s", before)
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	if got := appliedMigrations(t, st); !slices.Equal(got, files) {
		t.Errorf("after rerun applied %v", got)
	}
	if after := schema(t, st); after != before {
		t.Errorf("schema changed on rerun:\n%s\nvs\n%s", before, after)
	}
}

// Every older release upgrades to the same schema a fresh install gets:
// replay the first k migrations by hand, then let Migrate finish.
func TestMigrateUpgradesFromEveryVersion(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	want := schema(t, st)
	files := migrationFiles(t)

	for k := 0; k < len(files); k++ {
		if _, err := st.Pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
			t.Fatal(err)
		}
		if k > 0 {
			if _, err := st.Pool.Exec(ctx, `CREATE TABLE schema_migrations (
				filename TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
				t.Fatal(err)
			}
		}
		for _, name := range files[:k] {
			sql, err := migrations.FS.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := st.Pool.Exec(ctx, string(sql)); err != nil {
				t.Fatalf("replay %s: %v", name, err)
			}
			if _, err := st.Pool.Exec(ctx, `INSERT INTO schema_migrations (filename) VALUES ($1)`, name); err != nil {
				t.Fatal(err)
			}
		}
		if err := st.Migrate(ctx); err != nil {
			t.Fatalf("upgrade from %d applied: %v", k, err)
		}
		if got := schema(t, st); got != want {
			t.Errorf("upgrade from %d applied migrations differs from a fresh install", k)
		}
		if got := appliedMigrations(t, st); !slices.Equal(got, files) {
			t.Errorf("upgrade from %d: applied %v", k, got)
		}
	}
}
