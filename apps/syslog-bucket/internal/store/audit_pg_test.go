package store_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/syslog-yard/syslog-bucket/internal/store"
	"github.com/syslog-yard/syslog-bucket/internal/store/storetest"
)

func seedAudit(t *testing.T, st *store.Store) time.Time {
	t.Helper()
	ctx := context.Background()
	alice, bob := int64(1), int64(2)
	base := time.Now().Add(-time.Hour).Truncate(time.Second)
	var events []store.AuditEvent
	for i := range 10 {
		e := store.AuditEvent{
			Time: base.Add(time.Duration(i) * time.Minute), ActorID: &alice, ActorName: "Alice",
			ActorIP: "192.0.2.1", Action: "rule.update", TargetType: "rule", TargetID: "7",
			Summary: json.RawMessage(`{"name":"r"}`), Success: true,
		}
		if i%2 == 1 {
			e.ActorID, e.ActorName, e.Action, e.TargetType, e.TargetID = &bob, "bob", "entry.update", "entry", "42"
		}
		events = append(events, e)
	}
	// A failed sign-in: no account, the tried name as actor, no summary.
	events = append(events, store.AuditEvent{
		Time: base.Add(30 * time.Minute), ActorName: "mallory", Action: "auth.login", TargetType: "user",
	})
	if err := st.InsertAudit(ctx, events); err != nil {
		t.Fatal(err)
	}
	return base
}

func TestAuditInsertAndFilter(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	base := seedAudit(t, st)

	all, next, err := st.ListAudit(ctx, store.AuditFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 11 || next != nil {
		t.Fatalf("got %d events (next %v), want 11 and no next page", len(all), next)
	}
	for i := 1; i < len(all); i++ {
		if all[i].Time.After(all[i-1].Time) {
			t.Fatalf("not newest first at %d: %v after %v", i, all[i].Time, all[i-1].Time)
		}
	}
	if all[0].Action != "auth.login" || all[0].ActorID != nil || all[0].Success || string(all[0].Summary) != "{}" {
		t.Errorf("failed sign-in row = %+v, summary %s", all[0], all[0].Summary)
	}

	count := func(f store.AuditFilter) int {
		t.Helper()
		got, _, err := st.ListAudit(ctx, f)
		if err != nil {
			t.Fatal(err)
		}
		return len(got)
	}
	bob := int64(2)
	yes, no := true, false
	since, until := base.Add(2*time.Minute), base.Add(6*time.Minute)
	cases := map[string]struct {
		f    store.AuditFilter
		want int
	}{
		"actor, case-insensitive":          {store.AuditFilter{Actor: "alice"}, 5},
		"actor id":                         {store.AuditFilter{ActorID: &bob}, 5},
		"failed sign-in by name":           {store.AuditFilter{Actor: "MALLORY"}, 1},
		"action":                           {store.AuditFilter{Action: "entry.update"}, 5},
		"target type":                      {store.AuditFilter{TargetType: "rule"}, 5},
		"target id":                        {store.AuditFilter{TargetType: "entry", TargetID: "42"}, 5},
		"success":                          {store.AuditFilter{Success: &yes}, 10},
		"failure":                          {store.AuditFilter{Success: &no}, 1},
		"since inclusive, until exclusive": {store.AuditFilter{Since: &since, Until: &until}, 4},
		"combined":                         {store.AuditFilter{Actor: "bob", Since: &since}, 4},
	}
	for name, c := range cases {
		if got := count(c.f); got != c.want {
			t.Errorf("%s: got %d, want %d", name, got, c.want)
		}
	}
}

func TestAuditCursorPaging(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	seedAudit(t, st)
	// Same timestamp for several rows: the id breaks the tie.
	same := time.Now()
	var tied []store.AuditEvent
	for range 3 {
		tied = append(tied, store.AuditEvent{Time: same, Action: "tag.create", Success: true})
	}
	if err := st.InsertAudit(ctx, tied); err != nil {
		t.Fatal(err)
	}

	seen := map[int64]bool{}
	var cursor *store.AuditCursor
	pages := 0
	for {
		page, next, err := st.ListAudit(ctx, store.AuditFilter{Limit: 4, Before: cursor})
		if err != nil {
			t.Fatal(err)
		}
		pages++
		for _, e := range page {
			if seen[e.ID] {
				t.Fatalf("event %d returned twice", e.ID)
			}
			seen[e.ID] = true
		}
		if next == nil {
			break
		}
		// Round-trip through the wire form, as the API does.
		c, err := store.ParseAuditCursor(next.String())
		if err != nil {
			t.Fatal(err)
		}
		cursor = &c
		if pages > 10 {
			t.Fatal("paging does not terminate")
		}
	}
	if len(seen) != 14 {
		t.Errorf("paged through %d events, want 14", len(seen))
	}
	if pages != 4 { // 4 + 4 + 4 + 2
		t.Errorf("took %d pages, want 4", pages)
	}
}

func TestParseAuditCursorRejectsGarbage(t *testing.T) {
	for _, s := range []string{"", "abc", "123", "-5", "12-x", "x-12"} {
		if _, err := store.ParseAuditCursor(s); err == nil {
			t.Errorf("ParseAuditCursor(%q) accepted", s)
		}
	}
}

func TestPruneAudit(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	old := time.Now().Add(-200 * 24 * time.Hour)
	if err := st.InsertAudit(ctx, []store.AuditEvent{
		{Time: old, Action: "rule.create", Success: true},
		{Time: old.Add(time.Hour), Action: "rule.update", Success: true},
		{Action: "rule.delete", Success: true}, // zero time: now
	}); err != nil {
		t.Fatal(err)
	}
	n, err := st.PruneAudit(ctx, 180*24*time.Hour)
	if err != nil || n != 2 {
		t.Fatalf("pruned %d, %v; want 2", n, err)
	}
	left, _, err := st.ListAudit(ctx, store.AuditFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 1 || left[0].Action != "rule.delete" {
		t.Fatalf("left %+v, want only the recent row", left)
	}
}
