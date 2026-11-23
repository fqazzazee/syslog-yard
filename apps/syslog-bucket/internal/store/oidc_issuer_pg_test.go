package store_test

import (
	"context"
	"testing"

	"github.com/syslog-yard/syslog-bucket/internal/store"
	"github.com/syslog-yard/syslog-bucket/internal/store/storetest"
	"github.com/syslog-yard/syslog-bucket/migrations"
)

// A database from before issuer binding, already holding SSO accounts,
// migrates cleanly and its accounts bind once to the configured issuer.
func TestOIDCIssuerMigrationKeepsExistingAccounts(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	if _, err := st.Pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;
		CREATE TABLE schema_migrations (filename TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	for _, name := range migrationFiles(t) {
		if name >= "0011" {
			break
		}
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
	var id int64
	if err := st.Pool.QueryRow(ctx, `INSERT INTO users (username, role, oidc_subject)
		VALUES ('sso-admin', 'admin', 'sub-1') RETURNING id`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool.Exec(ctx, `INSERT INTO users (username, role, password_hash)
		VALUES ('local', 'viewer', 'x')`); err != nil {
		t.Fatal(err)
	}

	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate a populated database: %v", err)
	}
	const issuer = "https://idp.example/realms/yard"
	bound, unbound, err := st.BindLegacyOIDCIssuer(ctx, issuer)
	if err != nil || bound != 1 || unbound != 0 {
		t.Fatalf("bind: bound=%d unbound=%d err=%v", bound, unbound, err)
	}
	got, err := st.GetUserByOIDCIdentity(ctx, issuer, "sub-1")
	if err != nil || got == nil || got.ID != id || got.Role != store.RoleAdmin {
		t.Fatalf("existing account after upgrade: %+v, %v", got, err)
	}

	// The same subject at another issuer is a separate account, the same
	// identity twice is refused, and binding never runs a second time.
	if _, err := st.CreateOIDCUser(ctx, store.User{Username: "other", Role: store.RoleViewer}, "https://other.example", "sub-1"); err != nil {
		t.Fatalf("same subject, new issuer: %v", err)
	}
	if _, err := st.CreateOIDCUser(ctx, store.User{Username: "dup", Role: store.RoleViewer}, issuer, "sub-1"); err == nil {
		t.Error("duplicate issuer and subject accepted")
	}
	if bound, _, err := st.BindLegacyOIDCIssuer(ctx, "https://other.example"); err != nil || bound != 0 {
		t.Errorf("second bind: bound=%d err=%v", bound, err)
	}
}
