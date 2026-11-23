package api

import (
	"context"
	"testing"

	"github.com/syslog-yard/syslog-bucket/internal/auth"
	"github.com/syslog-yard/syslog-bucket/internal/config"
	"github.com/syslog-yard/syslog-bucket/internal/store"
	"github.com/syslog-yard/syslog-bucket/internal/store/storetest"
)

// legacySSOUser creates an account the way releases before issuer binding did.
func legacySSOUser(t *testing.T, st *store.Store, name, subject string) store.User {
	t.Helper()
	u, err := st.CreateUser(context.Background(), store.User{Username: name, Role: store.RoleAdmin}, subject)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestLegacySSOAccountsBindToEnvIssuerOnce(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	u := legacySSOUser(t, st, "legacy", "sub-1")
	const envIssuer = "https://idp.example/realms/yard"
	s := &server{store: st, authSvc: auth.New(st, false), cfg: config.Config{OIDCIssuer: envIssuer + "/"}}

	s.applyStoredSettings(ctx)
	got, err := st.GetUserByOIDCIdentity(ctx, envIssuer, "sub-1")
	if err != nil || got == nil || got.ID != u.ID {
		t.Fatalf("existing user must keep signing in with the configured issuer: %+v, %v", got, err)
	}

	// A later restart under another issuer must not move or adopt anything.
	late := legacySSOUser(t, st, "late", "sub-2")
	s.cfg.OIDCIssuer = "https://other.example"
	s.applyStoredSettings(ctx)
	if got, _ := st.GetUserByOIDCIdentity(ctx, "https://other.example", "sub-1"); got != nil {
		t.Error("bound account moved to a new issuer")
	}
	if got, _ := st.GetUserByOIDCIdentity(ctx, "https://other.example", "sub-2"); got != nil {
		t.Errorf("unbound account %d adopted by a later issuer", late.ID)
	}
}

func TestLegacySSOAccountsBindToStoredIssuer(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	u := legacySSOUser(t, st, "legacy", "sub-1")
	const stored = "https://stored.example"
	// The stored row wins over env, and counts even while SSO is switched off.
	if err := st.PutSetting(ctx, "oidc", oidcSettings{Enabled: false, Issuer: stored}); err != nil {
		t.Fatal(err)
	}
	s := &server{store: st, authSvc: auth.New(st, false), cfg: config.Config{OIDCIssuer: "https://env.example"}}
	s.applyStoredSettings(ctx)
	if got, err := st.GetUserByOIDCIdentity(ctx, stored, "sub-1"); err != nil || got == nil || got.ID != u.ID {
		t.Fatalf("got %+v, %v", got, err)
	}
}

// With no provider configured at upgrade there is nothing to bind to, and an
// issuer configured later must not inherit the accounts.
func TestLegacySSOAccountsStayUnboundWithoutIssuer(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	legacySSOUser(t, st, "legacy", "sub-1")
	s := &server{store: st, authSvc: auth.New(st, false)}
	s.applyStoredSettings(ctx)

	s.cfg.OIDCIssuer = "https://new.example"
	s.applyStoredSettings(ctx)
	if got, _ := st.GetUserByOIDCIdentity(ctx, "https://new.example", "sub-1"); got != nil {
		t.Fatal("an issuer configured after the upgrade inherited an existing account")
	}
}
