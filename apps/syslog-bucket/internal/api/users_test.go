package api

import (
	"testing"

	"github.com/syslog-yard/syslog-bucket/internal/store"
)

func TestSessionsRevokedBy(t *testing.T) {
	admin := &store.User{Role: store.RoleAdmin}
	analyst := &store.User{Role: store.RoleAnalyst}
	viewer := &store.User{Role: store.RoleViewer}
	cases := []struct {
		name      string
		before    *store.User
		role      string
		disabled  bool
		pwReset   bool
		wantRevok bool
	}{
		{"profile edit only", analyst, store.RoleAnalyst, false, false, false},
		{"promotion", viewer, store.RoleAnalyst, false, false, false},
		{"admin to analyst", admin, store.RoleAnalyst, false, false, true},
		{"analyst to viewer", analyst, store.RoleViewer, false, false, true},
		{"admin to viewer", admin, store.RoleViewer, false, false, true},
		{"disable", viewer, store.RoleViewer, true, false, true},
		{"password reset", analyst, store.RoleAnalyst, false, true, true},
	}
	for _, c := range cases {
		if got := sessionsRevokedBy(c.before, c.role, c.disabled, c.pwReset); got != c.wantRevok {
			t.Errorf("%s: got %v, want %v", c.name, got, c.wantRevok)
		}
	}
}
