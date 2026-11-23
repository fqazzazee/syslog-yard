package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/syslog-yard/syslog-bucket/internal/store"
	"github.com/syslog-yard/syslog-bucket/internal/store/storetest"
)

func postLogin(svc *Service, username, password string) int {
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	r := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	svc.HandleLogin(w, r)
	return w.Code
}

// Parallel requests may not get more password checks than the per-source
// limit, however many arrive before the first check finishes.
func TestLoginBurstStaysWithinLimit(t *testing.T) {
	st := storetest.New(t)
	hash, err := HashPassword("the-real-password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateUser(context.Background(), store.User{
		Username: "burst", Role: store.RoleViewer, PasswordHash: hash,
	}, ""); err != nil {
		t.Fatal(err)
	}
	svc := New(st, false)

	var checked atomic.Int64
	var wg sync.WaitGroup
	for i := range 60 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if postLogin(svc, "burst", fmt.Sprintf("wrong-%d", i)) == http.StatusUnauthorized {
				checked.Add(1)
			}
		}()
	}
	wg.Wait()
	if n := checked.Load(); n > loginMaxFails {
		t.Errorf("%d passwords were checked, limit is %d", n, loginMaxFails)
	}
}

// What the throttle keeps per failed login does not grow with the username.
func TestLoginThrottleKeyIsFixedSize(t *testing.T) {
	st := storetest.New(t)
	svc := New(st, false)
	if code := postLogin(svc, strings.Repeat("u", 60000), "wrong-password"); code != http.StatusUnauthorized {
		t.Fatalf("status %d", code)
	}
	for _, tr := range []*throttle{svc.loginGuard.perSource, svc.loginGuard.perAccount} {
		tr.mu.Lock()
		for k := range tr.entries {
			if len(k) > 128 {
				t.Errorf("throttle retains a %d-byte key", len(k))
			}
		}
		tr.mu.Unlock()
	}
}

// An unusable admin password stops first start with a message naming the
// setting to fix.
func TestBootstrapNamesOverlongPassword(t *testing.T) {
	st := storetest.New(t)
	err := Bootstrap(context.Background(), st, strings.Repeat("p", 73))
	if err == nil || !strings.Contains(err.Error(), "BUCKET_ADMIN_PASSWORD") {
		t.Fatalf("err = %v, want one naming BUCKET_ADMIN_PASSWORD", err)
	}
}
