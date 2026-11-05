package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/syslog-yard/syslog-bucket/internal/audit"
	"github.com/syslog-yard/syslog-bucket/internal/auth"
	"github.com/syslog-yard/syslog-bucket/internal/store"
	"github.com/syslog-yard/syslog-bucket/internal/store/storetest"
)

type auditHarness struct {
	t   *testing.T
	st  *store.Store
	rec *audit.Recorder
	h   http.Handler
}

func newAuditHarness(t *testing.T) *auditHarness {
	st := storetest.New(t)
	authSvc := auth.New(st, false)
	rec := audit.New(st, 0)
	authSvc.SetAuditor(rec)
	s := &server{store: st, authSvc: authSvc, auditor: rec}
	return &auditHarness{t: t, st: st, rec: rec, h: authSvc.Middleware(s.routes())}
}

// do sends a JSON request as u (nil = anonymous) and returns the response.
func (a *auditHarness) do(u *store.User, method, path string, body any) *httptest.ResponseRecorder {
	a.t.Helper()
	b, _ := json.Marshal(body)
	r := httptest.NewRequest(method, path, strings.NewReader(string(b)))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = "192.0.2.10:4711"
	if u != nil {
		r = r.WithContext(auth.WithUser(r.Context(), u))
	}
	w := httptest.NewRecorder()
	a.h.ServeHTTP(w, r)
	return w
}

func (a *auditHarness) mustDo(u *store.User, want int, method, path string, body any) *httptest.ResponseRecorder {
	a.t.Helper()
	w := a.do(u, method, path, body)
	if w.Code != want {
		a.t.Fatalf("%s %s: status %d (%s), want %d", method, path, w.Code, strings.TrimSpace(w.Body.String()), want)
	}
	return w
}

// TestAuditNeverRecordsSecrets drives every endpoint that receives a secret —
// passwords, the OIDC client secret, SMTP passwords, webhook URLs — and then
// checks that none of them appears anywhere in the audit table, while the
// events themselves were recorded.
func TestAuditNeverRecordsSecrets(t *testing.T) {
	a := newAuditHarness(t)
	ctx := context.Background()

	hash, _ := auth.HashPassword("admin-pass-123")
	admin, err := a.st.CreateUser(ctx, store.User{Username: "root", Role: store.RoleAdmin, PasswordHash: hash}, "")
	if err != nil {
		t.Fatal(err)
	}
	idp := httptest.NewServer(http.NotFoundHandler()) // discovery probe fails fast, offline
	defer idp.Close()

	secrets := map[string]string{
		"created password":   "Created-Sekret-91x",
		"reset password":     "Reset-Sekret-82y",
		"wrong login":        "Wrong-Sekret-73z",
		"wrong old password": "WrongOld-Sekret-64w",
		"new own password":   "NewOwn-Sekret-55v",
		"oidc client secret": "Oidc-Sekret-46u",
		"smtp password":      "Smtp-Sekret-37t",
		"webhook url token":  "Hook-Sekret-28s",
		"edited webhook url": "Hook2-Sekret-19r",
	}

	// Accounts: create, edit + password reset.
	var carol store.User
	w := a.mustDo(&admin, 200, "POST", "/api/users",
		map[string]any{"username": "carol", "role": "analyst", "password": secrets["created password"]})
	json.Unmarshal(w.Body.Bytes(), &carol)
	a.mustDo(&admin, 200, "PUT", fmt.Sprintf("/api/users/%d", carol.ID),
		map[string]any{"role": "admin", "display_name": "Carol", "password": secrets["reset password"]})

	// Sign-in: a wrong password, then the right one.
	a.mustDo(nil, 401, "POST", "/api/auth/login", map[string]any{"username": "carol", "password": secrets["wrong login"]})
	a.mustDo(nil, 200, "POST", "/api/auth/login", map[string]any{"username": "carol", "password": secrets["reset password"]})

	// Own password change: wrong current password, then a real change.
	me, _ := a.st.GetUser(ctx, carol.ID)
	a.mustDo(me, 403, "PUT", "/api/auth/password", map[string]any{"old": secrets["wrong old password"], "new": secrets["new own password"]})
	a.mustDo(me, 204, "PUT", "/api/auth/password", map[string]any{"old": secrets["reset password"], "new": secrets["new own password"]})

	// OIDC: set a secret, then save again keeping it.
	oidc := map[string]any{"enabled": true, "issuer": idp.URL, "client_id": "yard",
		"client_secret": secrets["oidc client secret"], "redirect_url": "http://localhost/api/auth/oidc/callback"}
	a.mustDo(&admin, 200, "PUT", "/api/settings/oidc", oidc)
	oidc["client_secret"], oidc["name"] = "", "Company SSO"
	a.mustDo(&admin, 200, "PUT", "/api/settings/oidc", oidc)
	a.mustDo(&admin, 200, "PUT", "/api/settings/session", map[string]any{"idle_minutes": 60})

	// Channels: an SMTP password and webhook URLs.
	a.mustDo(&admin, 200, "POST", "/api/channels", map[string]any{"name": "mail", "kind": "smtp", "enabled": true,
		"config": map[string]any{"host": "mail.example.com", "username": "bot", "password": secrets["smtp password"],
			"from": "yard@example.com", "to": []string{"soc@example.com"}}})
	var hook store.Channel
	w = a.mustDo(&admin, 200, "POST", "/api/channels", map[string]any{"name": "hook", "kind": "webhook", "enabled": true,
		"config": map[string]any{"url": "https://hooks.example.com/" + secrets["webhook url token"]}})
	json.Unmarshal(w.Body.Bytes(), &hook)
	a.mustDo(&admin, 200, "PUT", fmt.Sprintf("/api/channels/%d", hook.ID), map[string]any{"name": "hook", "kind": "webhook",
		"enabled": true, "config": map[string]any{"url": "https://hooks.example.com/" + secrets["edited webhook url"]}})

	a.rec.Shutdown(5 * time.Second)

	var dump string
	if err := a.st.Pool.QueryRow(ctx,
		`SELECT coalesce(string_agg(to_jsonb(a)::text, E'\n' ORDER BY id), '') FROM audit_log a`).Scan(&dump); err != nil {
		t.Fatal(err)
	}
	for what, secret := range secrets {
		if strings.Contains(dump, secret) {
			t.Errorf("the %s appears in the audit log", what)
		}
	}
	if strings.Contains(dump, "$2a$") {
		t.Error("a bcrypt hash appears in the audit log")
	}

	events, _, err := a.st.ListAudit(ctx, store.AuditFilter{Limit: 500})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]store.AuditEvent{}
	for _, e := range events {
		got[e.Action] = append(got[e.Action], e)
		if e.ActorIP != "192.0.2.10" {
			t.Errorf("%s: actor ip %q, want the client address", e.Action, e.ActorIP)
		}
	}
	want := map[string]int{
		audit.UserCreate: 1, audit.UserUpdate: 1, audit.UserPasswordReset: 1,
		audit.SignIn: 2, audit.PasswordChange: 2,
		audit.SettingsOIDC: 2, audit.SettingsSession: 1,
		audit.ChannelCreate: 2, audit.ChannelUpdate: 1,
	}
	for action, n := range want {
		if len(got[action]) != n {
			t.Errorf("%s recorded %d times, want %d", action, len(got[action]), n)
		}
	}
	if len(events) != 13 {
		t.Errorf("%d events recorded, want 13", len(events))
	}

	// Newest first: the failed sign-in is the older of the two.
	if s := got[audit.SignIn]; len(s) == 2 {
		ok, failed := s[0], s[1]
		if failed.Success || failed.ActorID != nil || failed.ActorName != "carol" {
			t.Errorf("failed sign-in = %+v", failed)
		}
		if !ok.Success || ok.ActorID == nil || *ok.ActorID != carol.ID {
			t.Errorf("sign-in = %+v", ok)
		}
	}
	if u := got[audit.UserUpdate]; len(u) == 1 {
		var sum map[string]any
		json.Unmarshal(u[0].Summary, &sum)
		role, _ := sum["role"].(map[string]any)
		if role["from"] != "analyst" || role["to"] != "admin" || u[0].ActorName != "root" {
			t.Errorf("user.update = %s by %s", u[0].Summary, u[0].ActorName)
		}
	}
	if o := got[audit.SettingsOIDC]; len(o) == 2 {
		if !strings.Contains(string(o[1].Summary), `"client_secret": "replaced"`) ||
			!strings.Contains(string(o[0].Summary), `"client_secret": "kept"`) {
			t.Errorf("oidc summaries = %s / %s", o[1].Summary, o[0].Summary)
		}
	}
	if c := got[audit.ChannelUpdate]; len(c) == 1 && !strings.Contains(string(c[0].Summary), `"config_changed": true`) {
		t.Errorf("channel.update = %s, want config_changed", c[0].Summary)
	}
}

// Triage and CRUD events carry compact summaries naming what changed.
func TestAuditTriageAndCRUD(t *testing.T) {
	a := newAuditHarness(t)
	ctx := context.Background()
	ana, err := a.st.CreateUser(ctx, store.User{Username: "ana", Role: store.RoleAnalyst}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.st.InsertEntries(ctx, []store.Entry{{ReceivedAt: time.Now(), Host: "h", Msg: "m", Status: "new"}}); err != nil {
		t.Fatal(err)
	}
	var entryID int64
	a.st.Pool.QueryRow(ctx, `SELECT id FROM entries`).Scan(&entryID)

	var tag store.Tag
	json.Unmarshal(a.mustDo(&ana, 200, "POST", "/api/tags", map[string]any{"name": "phish", "color": "#f00"}).Body.Bytes(), &tag)
	a.mustDo(&ana, 200, "PUT", fmt.Sprintf("/api/entries/%d/tags/%d", entryID, tag.ID), nil)
	a.mustDo(&ana, 200, "PATCH", fmt.Sprintf("/api/entries/%d", entryID), map[string]any{"status": "resolved", "priority": 3})
	a.mustDo(&ana, 200, "PUT", fmt.Sprintf("/api/entries/%d/mitre/T1110", entryID), nil)
	a.mustDo(&ana, 200, "DELETE", fmt.Sprintf("/api/entries/%d/tags/%d", entryID, tag.ID), nil)
	a.mustDo(&ana, 204, "DELETE", fmt.Sprintf("/api/tags/%d", tag.ID), nil)
	a.mustDo(&ana, 200, "POST", "/api/buckets", map[string]any{"name": "mine", "condition": map[string]any{}})
	a.rec.Shutdown(5 * time.Second)

	events, _, err := a.st.ListAudit(ctx, store.AuditFilter{})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for i := len(events) - 1; i >= 0; i-- {
		e := events[i]
		if e.ActorName != "ana" || e.ActorID == nil || *e.ActorID != ana.ID || !e.Success {
			t.Errorf("%s: actor %q/%v success %v", e.Action, e.ActorName, e.ActorID, e.Success)
		}
		got = append(got, e.Action+" "+e.TargetType+":"+e.TargetID+" "+string(e.Summary))
	}
	eid, tid := strconv.FormatInt(entryID, 10), strconv.FormatInt(tag.ID, 10)
	want := []string{
		`tag.create tag:` + tid + ` {"name": "phish"}`,
		`entry.tag entry:` + eid + ` {"tag_id": ` + tid + `}`,
		`entry.update entry:` + eid + ` {"status": "resolved", "priority": 3}`,
		`entry.classify entry:` + eid + ` {"op": "add", "mitre": "T1110"}`,
		`entry.untag entry:` + eid + ` {"tag_id": ` + tid + `}`,
		`tag.delete tag:` + tid + ` {"name": "phish"}`,
	}
	if len(got) != len(want)+1 || !strings.HasPrefix(got[len(want)], "bucket.create bucket:") {
		t.Fatalf("events:\n%s", strings.Join(got, "\n"))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("event %d:\n got %s\nwant %s", i, got[i], want[i])
		}
	}
}

// The audit endpoint pages with an opaque cursor and filters by actor.
func TestGetAuditPaging(t *testing.T) {
	a := newAuditHarness(t)
	ctx := context.Background()
	admin, err := a.st.CreateUser(ctx, store.User{Username: "root", Role: store.RoleAdmin}, "")
	if err != nil {
		t.Fatal(err)
	}
	var rows []store.AuditEvent
	for i := range 5 {
		rows = append(rows, store.AuditEvent{ActorName: []string{"ann", "ben"}[i%2], Action: audit.TagCreate, Success: true})
	}
	if err := a.st.InsertAudit(ctx, rows); err != nil {
		t.Fatal(err)
	}

	type page struct {
		Events []store.AuditEvent `json:"events"`
		Next   *string            `json:"next_cursor"`
	}
	read := func(path string) page {
		t.Helper()
		var p page
		json.Unmarshal(a.mustDo(&admin, 200, "GET", path, nil).Body.Bytes(), &p)
		return p
	}
	p1 := read("/api/audit?limit=2")
	if len(p1.Events) != 2 || p1.Next == nil {
		t.Fatalf("first page: %d events, next %v", len(p1.Events), p1.Next)
	}
	p2 := read("/api/audit?limit=2&cursor=" + *p1.Next)
	p3 := read("/api/audit?limit=2&cursor=" + *p2.Next)
	if len(p3.Events) != 1 || p3.Next != nil || p2.Events[0].ID >= p1.Events[1].ID {
		t.Errorf("paging: %d then %d then %d events (next %v)", len(p1.Events), len(p2.Events), len(p3.Events), p3.Next)
	}
	if ann := read("/api/audit?actor=ANN"); len(ann.Events) != 3 {
		t.Errorf("actor filter: %d events, want 3", len(ann.Events))
	}
	for _, bad := range []string{"since=yesterday", "cursor=nope", "limit=0", "success=maybe"} {
		a.mustDo(&admin, 400, "GET", "/api/audit?"+bad, nil)
	}
}
