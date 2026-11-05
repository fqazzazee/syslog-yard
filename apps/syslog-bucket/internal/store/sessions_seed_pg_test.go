package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/syslog-yard/syslog-bucket/internal/store"
	"github.com/syslog-yard/syslog-bucket/internal/store/storetest"
)

func TestCapSessionExpiry(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	u, err := st.CreateUser(ctx, store.User{Username: "u", Role: store.RoleViewer}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CreateSession(ctx, "long", u.ID, time.Now().Add(30*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := st.CreateSession(ctx, "short", u.ID, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	n, err := st.CapSessionExpiry(ctx, time.Hour)
	if err != nil || n != 1 {
		t.Fatalf("capped %d, %v; want 1", n, err)
	}
	var maxExp time.Time
	st.Pool.QueryRow(ctx, `SELECT max(expires_at) FROM sessions`).Scan(&maxExp)
	if time.Until(maxExp) > time.Hour+time.Minute {
		t.Errorf("session still expires at %v", maxExp)
	}
}

func TestSeedDefaultBucketsOnce(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	n, err := st.SeedDefaultBuckets(ctx)
	if err != nil || n == 0 {
		t.Fatalf("first seed = %d, %v", n, err)
	}
	if _, err := st.Pool.Exec(ctx, `DELETE FROM buckets`); err != nil {
		t.Fatal(err)
	}
	if n, err := st.SeedDefaultBuckets(ctx); err != nil || n != 0 {
		t.Errorf("reseeded %d buckets after the user deleted them (err %v)", n, err)
	}
}

// An install that predates the marker but already has buckets is marked
// without seeding, so a later "delete all" sticks.
func TestSeedDefaultBucketsMarksExistingInstall(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	if _, err := st.CreateBucket(ctx, store.Bucket{Name: "mine"}); err != nil {
		t.Fatal(err)
	}
	if n, err := st.SeedDefaultBuckets(ctx); err != nil || n != 0 {
		t.Fatalf("seed = %d, %v", n, err)
	}
	st.Pool.Exec(ctx, `DELETE FROM buckets`)
	if n, _ := st.SeedDefaultBuckets(ctx); n != 0 {
		t.Errorf("reseeded %d", n)
	}
}
