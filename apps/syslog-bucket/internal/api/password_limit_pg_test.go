package api

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/syslog-yard/syslog-bucket/internal/auth"
	"github.com/syslog-yard/syslog-bucket/internal/store"
)

// bcrypt can't hash more than 72 bytes: every path that sets a password
// answers that as a validation error rather than a 500.
func TestPasswordOverLimitIsRejected(t *testing.T) {
	a := newAuditHarness(t)
	ctx := context.Background()
	hash, _ := auth.HashPassword("admin-pass-123")
	admin, err := a.st.CreateUser(ctx, store.User{Username: "root", Role: store.RoleAdmin, PasswordHash: hash}, "")
	if err != nil {
		t.Fatal(err)
	}
	tooLong, longest := strings.Repeat("p", 73), strings.Repeat("p", 72)

	a.mustDo(&admin, 400, "POST", "/api/users", map[string]any{"username": "u1", "role": "viewer", "password": tooLong})
	a.mustDo(&admin, 200, "POST", "/api/users", map[string]any{"username": "u2", "role": "viewer", "password": longest})
	a.mustDo(&admin, 400, "PUT", fmt.Sprintf("/api/users/%d", admin.ID),
		map[string]any{"role": "admin", "password": tooLong})
	a.mustDo(&admin, 400, "PUT", "/api/auth/password", map[string]any{"old": "admin-pass-123", "new": tooLong})
}
