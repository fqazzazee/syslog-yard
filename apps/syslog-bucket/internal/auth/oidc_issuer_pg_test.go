package auth

import (
	"context"
	"testing"

	"github.com/syslog-yard/syslog-bucket/internal/store"
	"github.com/syslog-yard/syslog-bucket/internal/store/storetest"
)

// An account belongs to the issuer that created it: the same subject at
// another issuer is a different person.
func TestOIDCSubjectIsBoundToIssuer(t *testing.T) {
	st := storetest.New(t)
	svc := New(st, false)
	ctx := context.Background()
	first := &OIDC{Issuer: "https://idp-one.example/realms/a", DefaultRole: store.RoleViewer}
	second := &OIDC{Issuer: "https://idp-two.example/realms/b", DefaultRole: store.RoleViewer}

	a, err := svc.userForSubject(ctx, first, "42", "alice", "", "")
	if err != nil {
		t.Fatal(err)
	}
	again, err := svc.userForSubject(ctx, &OIDC{Issuer: first.Issuer + "/"}, "42", "alice", "", "")
	if err != nil || again.ID != a.ID {
		t.Fatalf("same issuer should find the same account: %+v, %v", again, err)
	}
	b, err := svc.userForSubject(ctx, second, "42", "alice", "", "")
	if err != nil {
		t.Fatalf("new issuer, colliding subject and username: %v", err)
	}
	if b.ID == a.ID {
		t.Fatal("a user at another issuer signed in to the existing account")
	}
	if b.Role != store.RoleViewer {
		t.Errorf("new account role = %q", b.Role)
	}
}
