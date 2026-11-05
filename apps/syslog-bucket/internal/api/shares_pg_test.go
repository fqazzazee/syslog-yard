package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/syslog-yard/syslog-bucket/internal/auth"
	"github.com/syslog-yard/syslog-bucket/internal/rules"
	"github.com/syslog-yard/syslog-bucket/internal/store"
	"github.com/syslog-yard/syslog-bucket/internal/store/storetest"
	"github.com/syslog-yard/syslog-bucket/internal/ws"
)

type apiClient struct {
	t *testing.T
	h http.Handler
}

func newAPI(t *testing.T, st *store.Store) apiClient {
	authSvc := auth.New(st, false)
	s := &server{store: st, authSvc: authSvc, hub: ws.NewHub(), hints: map[string]string{},
		web: fstest.MapFS{"index.html": {Data: []byte("<html></html>")}}}
	return apiClient{t: t, h: authSvc.Middleware(s.routes())}
}

// do sends a request as u and decodes a JSON reply into out (if non-nil).
func (c apiClient) do(u *store.User, method, path string, body any, out any) int {
	c.t.Helper()
	var rd *strings.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			c.t.Fatal(err)
		}
		rd = strings.NewReader(string(b))
	} else {
		rd = strings.NewReader("")
	}
	r := httptest.NewRequest(method, path, rd)
	r.Header.Set("Content-Type", "application/json")
	r = r.WithContext(auth.WithUser(r.Context(), u))
	w := httptest.NewRecorder()
	c.h.ServeHTTP(w, r)
	if out != nil && w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), out); err != nil {
			c.t.Fatalf("%s %s: decode %q: %v", method, path, w.Body.String(), err)
		}
	}
	return w.Code
}

func mkUser(t *testing.T, st *store.Store, name, role string) *store.User {
	t.Helper()
	u, err := st.CreateUser(context.Background(), store.User{Username: name, Role: role}, "")
	if err != nil {
		t.Fatal(err)
	}
	return &u
}

// Share permissions end to end through the API: who sees a bucket, who may
// edit it, and who may delete it or change its sharing.
func TestBucketSharePermissions(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	api := newAPI(t, st)

	admin := mkUser(t, st, "admin", store.RoleAdmin)
	owner := mkUser(t, st, "owner", store.RoleAnalyst)
	viewer := mkUser(t, st, "view-share", store.RoleAnalyst)
	editor := mkUser(t, st, "edit-share", store.RoleAnalyst)
	stranger := mkUser(t, st, "stranger", store.RoleAnalyst)
	roViewer := mkUser(t, st, "viewer-role", store.RoleViewer)

	if err := st.InsertEntries(ctx, []store.Entry{
		{ReceivedAt: time.Now(), Host: "secret-host", Msg: "x", Status: "new"},
		{ReceivedAt: time.Now(), Host: "other", Msg: "y", Status: "new"},
	}); err != nil {
		t.Fatal(err)
	}

	var b store.Bucket
	if code := api.do(owner, "POST", "/api/buckets", store.Bucket{Name: "mine",
		Condition: rules.Cond{Field: "host", Op: "eq", Value: "secret-host"}}, &b); code != 200 || b.ID == 0 {
		t.Fatalf("create bucket: %d %+v", code, b)
	}
	bucket := fmt.Sprintf("/api/buckets/%d", b.ID)
	shares := bucket + "/shares"

	// Before sharing, only the owner and admins see it.
	if code := api.do(stranger, "GET", shares, nil, nil); code != 404 {
		t.Errorf("stranger GET shares = %d, want 404", code)
	}
	if code := api.do(owner, "PUT", shares, map[string]any{"shares": []store.BucketShare{
		{UserID: viewer.ID}, {UserID: editor.ID, CanEdit: true}, {UserID: roViewer.ID, CanEdit: true},
	}}, nil); code != 200 {
		t.Fatalf("owner PUT shares = %d", code)
	}

	visible := func(u *store.User) (seen, canEdit bool) {
		t.Helper()
		var resp struct{ Buckets []store.Bucket }
		if code := api.do(u, "GET", "/api/buckets", nil, &resp); code != 200 {
			t.Fatalf("%s list buckets = %d", u.Username, code)
		}
		for _, x := range resp.Buckets {
			if x.ID == b.ID {
				return true, x.CanEdit
			}
		}
		return false, false
	}
	update := func(u *store.User, name string) int {
		return api.do(u, "PUT", bucket, store.Bucket{Name: name, Condition: b.Condition}, nil)
	}
	entries := func(u *store.User) (int, []store.Entry) {
		var resp struct{ Entries []store.Entry }
		code := api.do(u, "GET", fmt.Sprintf("/api/entries?bucket_id=%d", b.ID), nil, &resp)
		return code, resp.Entries
	}

	cases := []struct {
		u                         *store.User
		seen, canEdit             bool
		update, del, getSh, putSh int
		entries                   int
	}{
		{owner, true, true, 200, 0, 200, 0, 200},
		{admin, true, true, 200, 0, 200, 0, 200},
		{editor, true, true, 200, 403, 403, 403, 200},
		{viewer, true, false, 403, 403, 403, 403, 200},
		// The share says can_edit, but the viewer role stays read-only.
		{roViewer, true, true, 403, 403, 403, 403, 200},
		{stranger, false, false, 404, 404, 404, 404, 400},
	}
	for _, c := range cases {
		name := c.u.Username
		seen, canEdit := visible(c.u)
		if seen != c.seen || canEdit != c.canEdit {
			t.Errorf("%s: listed=%v can_edit=%v, want %v %v", name, seen, canEdit, c.seen, c.canEdit)
		}
		if code := update(c.u, "renamed by "+name); code != c.update {
			t.Errorf("%s PUT bucket = %d, want %d", name, code, c.update)
		}
		if c.del != 0 {
			if code := api.do(c.u, "DELETE", bucket, nil, nil); code != c.del {
				t.Errorf("%s DELETE bucket = %d, want %d", name, code, c.del)
			}
		}
		if code := api.do(c.u, "GET", shares, nil, nil); code != c.getSh {
			t.Errorf("%s GET shares = %d, want %d", name, code, c.getSh)
		}
		if c.putSh != 0 {
			// Nobody but the owner or an admin may grant themselves more.
			body := map[string]any{"shares": []store.BucketShare{{UserID: c.u.ID, CanEdit: true}}}
			if code := api.do(c.u, "PUT", shares, body, nil); code != c.putSh {
				t.Errorf("%s PUT shares = %d, want %d", name, code, c.putSh)
			}
		}
		code, got := entries(c.u)
		if code != c.entries {
			t.Errorf("%s entries?bucket_id = %d, want %d", name, code, c.entries)
		}
		if code == 200 && (len(got) != 1 || got[0].Host != "secret-host") {
			t.Errorf("%s bucket entries = %+v, want only secret-host", name, got)
		}
	}

	// Shares survive the failed attempts unchanged.
	var listed struct{ Shares []store.BucketShare }
	if code := api.do(owner, "GET", shares, nil, &listed); code != 200 || len(listed.Shares) != 3 {
		t.Fatalf("shares after denied changes = %d %+v", code, listed.Shares)
	}
	for _, sh := range listed.Shares {
		if want := sh.UserID != viewer.ID; sh.CanEdit != want {
			t.Errorf("share for %s can_edit=%v, want %v", sh.Username, sh.CanEdit, want)
		}
	}

	// Revoking a share hides the bucket again.
	if code := api.do(owner, "PUT", shares, map[string]any{"shares": []store.BucketShare{{UserID: editor.ID, CanEdit: false}}}, nil); code != 200 {
		t.Fatalf("owner revoke = %d", code)
	}
	if seen, _ := visible(viewer); seen {
		t.Error("revoked viewer still sees the bucket")
	}
	if code := update(editor, "after downgrade"); code != 403 {
		t.Errorf("downgraded editor PUT = %d, want 403", code)
	}
	if code := api.do(viewer, "PUT", bucket, store.Bucket{Name: "x"}, nil); code != 404 {
		t.Errorf("revoked viewer PUT = %d, want 404", code)
	}

	// The owner deletes; the shares go with the bucket.
	if code := api.do(owner, "DELETE", bucket, nil, nil); code != 204 {
		t.Errorf("owner DELETE = %d, want 204", code)
	}
	if left, err := st.ListBucketShares(ctx, b.ID); err != nil || len(left) != 0 {
		t.Errorf("shares left after delete: %v %v", left, err)
	}
}

// Ownerless yard buckets: every signed-in user sees them, analysts and admins
// edit and manage them, viewers only read.
func TestYardBucketPermissions(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	api := newAPI(t, st)
	analyst := mkUser(t, st, "analyst", store.RoleAnalyst)
	viewer := mkUser(t, st, "viewer", store.RoleViewer)
	yard, err := st.CreateBucket(ctx, store.Bucket{Name: "yard", Condition: rules.Cond{}})
	if err != nil {
		t.Fatal(err)
	}
	path := fmt.Sprintf("/api/buckets/%d", yard.ID)

	var got struct{ Buckets []store.Bucket }
	if code := api.do(viewer, "GET", "/api/buckets", nil, &got); code != 200 || len(got.Buckets) != 1 || got.Buckets[0].CanEdit {
		t.Errorf("viewer list = %d %+v, want the yard bucket read-only", code, got.Buckets)
	}
	if code := api.do(viewer, "GET", path+"/shares", nil, nil); code != 403 {
		t.Errorf("viewer GET shares = %d, want 403", code)
	}
	if code := api.do(analyst, "GET", "/api/buckets", nil, &got); code != 200 || len(got.Buckets) != 1 || !got.Buckets[0].CanEdit {
		t.Errorf("analyst list = %d %+v, want the yard bucket editable", code, got.Buckets)
	}
	if code := api.do(analyst, "PUT", path, store.Bucket{Name: "renamed"}, nil); code != 200 {
		t.Errorf("analyst PUT = %d, want 200", code)
	}
	if code := api.do(analyst, "GET", path+"/shares", nil, nil); code != 200 {
		t.Errorf("analyst GET shares = %d, want 200", code)
	}
	if code := api.do(analyst, "DELETE", path, nil, nil); code != 204 {
		t.Errorf("analyst DELETE = %d, want 204", code)
	}
}
