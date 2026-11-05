package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/syslog-yard/syslog-bucket/internal/auth"
	"github.com/syslog-yard/syslog-bucket/internal/store"
	"github.com/syslog-yard/syslog-bucket/internal/ws"
)

// policy is the least privilege a route needs.
type policy int

const (
	public  policy = iota // no session needed
	signed                // any signed-in user, viewers included (reads, own account)
	analyst               // analyst or admin
	admin                 // admin only
)

// routePolicy lists every registered route with the role it requires. A route
// added to routes() without an entry here fails TestRouteAuthz, so new
// endpoints get an explicit authorisation decision.
var routePolicy = map[string]policy{
	"GET /api/healthz":                      public,
	"GET /api/hints":                        public,
	"GET /api/auth/info":                    public,
	"POST /api/auth/login":                  public,
	"GET /api/auth/oidc/login":              public,
	"GET /api/auth/oidc/callback":           public,
	"GET /":                                 public, // SPA; renders the login page itself
	"POST /api/auth/logout":                 signed,
	"GET /api/auth/me":                      signed,
	"PUT /api/auth/password":                signed,
	"GET /api/mitre":                        signed,
	"GET /api/mitre/summary":                signed,
	"GET /api/ot":                           signed,
	"GET /api/ot/summary":                   signed,
	"GET /api/class/summary":                signed,
	"GET /api/net/summary":                  signed,
	"GET /api/net/entries":                  signed,
	"GET /api/net/config":                   signed,
	"GET /api/coverage":                     signed,
	"GET /api/frameworks":                   signed,
	"GET /api/users":                        signed, // share picker
	"GET /api/buckets/{id}/shares":          signed, // + owner/admin check in the handler
	"GET /api/entries":                      signed,
	"GET /api/entries/{id}":                 signed,
	"GET /api/sources":                      signed,
	"GET /api/stats":                        signed,
	"GET /api/tags":                         signed,
	"GET /api/buckets":                      signed,
	"GET /api/rules":                        signed,
	"GET /api/channels":                     signed, // URLs masked for viewers
	"GET /api/notifications/log":            signed, // URLs masked for viewers
	"GET /api/ws":                           signed,
	"PATCH /api/entries/{id}":               analyst,
	"PUT /api/entries/{id}/tags/{tag}":      analyst,
	"DELETE /api/entries/{id}/tags/{tag}":   analyst,
	"PUT /api/entries/{id}/mitre/{code}":    analyst,
	"DELETE /api/entries/{id}/mitre/{code}": analyst,
	"PUT /api/entries/{id}/ot/{code}":       analyst,
	"DELETE /api/entries/{id}/ot/{code}":    analyst,
	"POST /api/tags":                        analyst,
	"PUT /api/tags/{id}":                    analyst,
	"DELETE /api/tags/{id}":                 analyst,
	"POST /api/buckets":                     analyst,
	"PUT /api/buckets/{id}":                 analyst, // + can_edit check in the handler
	"DELETE /api/buckets/{id}":              analyst, // + owner/admin check in the handler
	"PUT /api/buckets/{id}/shares":          analyst, // + owner/admin check in the handler
	"POST /api/rules":                       analyst,
	"PUT /api/rules/{id}":                   analyst,
	"DELETE /api/rules/{id}":                analyst,
	"POST /api/rules/{id}/apply":            analyst,
	"POST /api/channels":                    analyst,
	"PUT /api/channels/{id}":                analyst,
	"DELETE /api/channels/{id}":             analyst,
	"POST /api/channels/{id}/test":          analyst,
	"GET /api/settings":                     admin,
	"PUT /api/settings/oidc":                admin,
	"PUT /api/settings/session":             admin,
	"POST /api/users":                       admin,
	"PUT /api/users/{id}":                   admin,
	"DELETE /api/users/{id}":                admin,
	"POST /api/frameworks":                  admin,
	"PUT /api/frameworks/{id}":              admin,
	"DELETE /api/frameworks/{id}":           admin,
	"PUT /api/net/config":                   admin,
	"POST /api/net/refresh":                 admin,
}

var routeRE = regexp.MustCompile(`mux\.HandleFunc\("([A-Z]+ [^"]+)"`)

// registeredRoutes reads the patterns straight from the source of routes(),
// since ServeMux can't enumerate them.
func registeredRoutes(t *testing.T) []string {
	t.Helper()
	src, err := os.ReadFile("api.go")
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, m := range routeRE.FindAllStringSubmatch(string(src), -1) {
		out = append(out, m[1])
	}
	if len(out) < 50 {
		t.Fatalf("found only %d routes in api.go; did registration move?", len(out))
	}
	return out
}

var pathParam = strings.NewReplacer("{id}", "1", "{tag}", "1", "{code}", "T1059")

// TestRouteAuthz drives the real middleware + router as each role, with no
// database: a nil store makes any handler that gets past its role checks
// panic on its first query, which the test counts as "let through". So the
// test asserts exactly the 401/403 decisions taken before data is touched;
// per-object rules (bucket ownership, shares) are covered by
// TestCanManageBucket and the store's visibility SQL.
func TestRouteAuthz(t *testing.T) {
	authSvc := auth.New(nil, false)
	s := &server{authSvc: authSvc, hub: ws.NewHub(), hints: map[string]string{},
		web: fstest.MapFS{"index.html": {Data: []byte("<html></html>")}}}
	h := authSvc.Middleware(s.routes())

	users := map[string]*store.User{
		"anonymous": nil,
		"viewer":    {ID: 3, Role: store.RoleViewer},
		"analyst":   {ID: 2, Role: store.RoleAnalyst},
		"admin":     {ID: 1, Role: store.RoleAdmin},
	}
	rank := map[string]policy{"anonymous": public, "viewer": signed, "analyst": analyst, "admin": admin}

	registered := registeredRoutes(t)
	seen := map[string]bool{}
	for _, route := range registered {
		seen[route] = true
		need, ok := routePolicy[route]
		if !ok {
			t.Errorf("route %q has no entry in routePolicy — decide who may call it", route)
			continue
		}
		method, pattern, _ := strings.Cut(route, " ")
		for name, u := range users {
			r := httptest.NewRequest(method, pathParam.Replace(pattern), strings.NewReader("{}"))
			r.Header.Set("Content-Type", "application/json")
			if u != nil {
				r = r.WithContext(auth.WithUser(r.Context(), u))
			}
			code, reached := serveRecover(h, r)
			denied := !reached && (code == http.StatusUnauthorized || code == http.StatusForbidden)
			if wantDenied := rank[name] < need; denied != wantDenied {
				t.Errorf("%s as %s: status %d (reached store: %v), want denied=%v",
					route, name, code, reached, wantDenied)
			}
		}
	}
	for route := range routePolicy {
		if !seen[route] {
			t.Errorf("routePolicy lists %q, which is not registered", route)
		}
	}
}

func serveRecover(h http.Handler, r *http.Request) (code int, panicked bool) {
	w := httptest.NewRecorder()
	func() {
		defer func() {
			if recover() != nil {
				panicked = true
			}
		}()
		h.ServeHTTP(w, r)
	}()
	return w.Code, panicked
}

func TestCanManageBucket(t *testing.T) {
	owner := int64(7)
	owned := &store.Bucket{OwnerID: &owner}
	yard := &store.Bucket{}
	cases := []struct {
		name string
		u    *store.User
		b    *store.Bucket
		want bool
	}{
		{"admin, someone else's", &store.User{ID: 1, Role: store.RoleAdmin}, owned, true},
		{"owner", &store.User{ID: 7, Role: store.RoleAnalyst}, owned, true},
		{"other analyst", &store.User{ID: 8, Role: store.RoleAnalyst}, owned, false},
		{"analyst, yard bucket", &store.User{ID: 8, Role: store.RoleAnalyst}, yard, true},
		{"viewer, yard bucket", &store.User{ID: 9, Role: store.RoleViewer}, yard, false},
	}
	for _, c := range cases {
		if got := canManageBucket(c.u, c.b); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
