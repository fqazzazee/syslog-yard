package store_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/syslog-yard/syslog-bucket/internal/rules"
	"github.com/syslog-yard/syslog-bucket/internal/store"
	"github.com/syslog-yard/syslog-bucket/internal/store/storetest"
)

func entryTagRows(t *testing.T, st *store.Store, entryID int64) map[int64]*int64 {
	t.Helper()
	rows, err := st.Pool.Query(context.Background(), `SELECT tag_id, rule_id FROM entry_tags WHERE entry_id = $1`, entryID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[int64]*int64{}
	for rows.Next() {
		var tag int64
		var rule *int64
		if err := rows.Scan(&tag, &rule); err != nil {
			t.Fatal(err)
		}
		out[tag] = rule
	}
	return out
}

// A tag or rule deleted while its entries sat in the ingest queue must not
// fail the batch: the entries commit, the vanished tag is skipped, and a
// vanished rule's attribution becomes NULL.
func TestInsertEntriesSurvivesDeletedTagAndRule(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	keep, _ := st.CreateTag(ctx, store.Tag{Name: "keep"})
	gone, _ := st.CreateTag(ctx, store.Tag{Name: "gone"})
	rule, err := st.CreateRule(ctx, store.Rule{Name: "r", Actions: []rules.Action{{Type: "suppress"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteTag(ctx, gone.ID); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteRule(ctx, rule.ID); err != nil {
		t.Fatal(err)
	}

	batch := []store.Entry{
		{ReceivedAt: time.Now(), Host: "h", Msg: "one", Status: "new",
			TagIDs:   []int64{keep.ID, gone.ID},
			RuleTags: []store.RuleTag{{TagID: keep.ID, RuleID: rule.ID}, {TagID: gone.ID, RuleID: rule.ID}}},
		{ReceivedAt: time.Now(), Host: "h", Msg: "two", Status: "new"},
	}
	if err := st.InsertEntries(ctx, batch); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if batch[0].ID == 0 || batch[1].ID == 0 {
		t.Fatalf("ids not filled: %+v", batch)
	}
	got := entryTagRows(t, st, batch[0].ID)
	if len(got) != 1 || got[keep.ID] != nil {
		t.Errorf("entry_tags = %v, want only keep with NULL rule", got)
	}
	if len(batch[0].TagIDs) != 1 || batch[0].TagIDs[0] != keep.ID {
		t.Errorf("TagIDs = %v, want [%d]", batch[0].TagIDs, keep.ID)
	}
}

func TestInsertEntriesIsAtomic(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	bad := int64(999999) // no such source: FK violation on the second row
	batch := []store.Entry{
		{ReceivedAt: time.Now(), Host: "h", Msg: "ok", Status: "new"},
		{ReceivedAt: time.Now(), Host: "h", Msg: "bad", Status: "new", SourceID: &bad},
	}
	err := st.InsertEntries(ctx, batch)
	if err == nil {
		t.Fatal("expected FK error")
	}
	if store.IsTransient(err) {
		t.Errorf("FK violation classified transient: %v", err)
	}
	if batch[0].ID != 0 {
		t.Error("ids must be reset after a failed batch")
	}
	var n int
	st.Pool.QueryRow(ctx, `SELECT count(*) FROM entries`).Scan(&n)
	if n != 0 {
		t.Errorf("%d entries committed from a failed batch", n)
	}
}

func TestDeleteReferencedTagAndChannelConflict(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	tag, _ := st.CreateTag(ctx, store.Tag{Name: "t"})
	ch, err := st.CreateChannel(ctx, store.Channel{Name: "c", Kind: "webhook", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	rule, err := st.CreateRule(ctx, store.Rule{Name: "uses both", Enabled: true, Actions: []rules.Action{
		{Type: "tag", TagID: tag.ID}, {Type: "notify", ChannelID: ch.ID},
	}})
	if err != nil {
		t.Fatal(err)
	}

	err = st.DeleteTag(ctx, tag.ID)
	var inUse *store.InUseError
	if !errors.Is(err, store.ErrInUse) || !errors.As(err, &inUse) || len(inUse.Rules) != 1 || inUse.Rules[0] != "uses both" {
		t.Fatalf("DeleteTag err = %v", err)
	}
	if err := st.DeleteChannel(ctx, ch.ID); !errors.Is(err, store.ErrInUse) {
		t.Fatalf("DeleteChannel err = %v", err)
	}

	// Disabled rules don't block deletion.
	rule.Enabled = false
	if _, err := st.UpdateRule(ctx, rule); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteTag(ctx, tag.ID); err != nil {
		t.Errorf("DeleteTag after disabling rule: %v", err)
	}
	if err := st.DeleteChannel(ctx, ch.ID); err != nil {
		t.Errorf("DeleteChannel after disabling rule: %v", err)
	}

	mt, mc, err := st.MissingRuleRefs(ctx, []int64{tag.ID}, []int64{ch.ID})
	if err != nil || len(mt) != 1 || len(mc) != 1 {
		t.Errorf("MissingRuleRefs = %v %v %v", mt, mc, err)
	}
}

// The condition is evaluated once: set_priority must not change which entries
// the later tag action touches, and affected counts entries, not passes.
func TestApplyRuleHistoricalSnapshotsMatches(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	tag, _ := st.CreateTag(ctx, store.Tag{Name: "t"})
	ch, _ := st.CreateChannel(ctx, store.Channel{Name: "c", Kind: "webhook", Enabled: true})
	batch := []store.Entry{
		{ReceivedAt: time.Now(), Host: "a", Msg: "x", Status: "new"},
		{ReceivedAt: time.Now(), Host: "a", Msg: "y", Status: "new"},
		{ReceivedAt: time.Now(), Host: "b", Msg: "z", Status: "new"},
	}
	if err := st.InsertEntries(ctx, batch); err != nil {
		t.Fatal(err)
	}
	rule, err := st.CreateRule(ctx, store.Rule{Name: "r", Enabled: true,
		Condition: rules.Cond{All: []rules.Cond{
			{Field: "host", Op: "eq", Value: "a"},
			{Field: "priority", Op: "eq", Value: float64(0)},
		}},
		Actions: []rules.Action{
			{Type: "set_priority", Priority: 2},
			{Type: "tag", TagID: tag.ID},
			{Type: "notify", ChannelID: ch.ID},
		}})
	if err != nil {
		t.Fatal(err)
	}
	res, err := st.ApplyRuleHistorical(ctx, rule)
	if err != nil {
		t.Fatal(err)
	}
	if res.Matched != 2 || res.Affected != 2 {
		t.Errorf("result = %+v, want matched 2 affected 2", res)
	}
	if len(res.Skipped) != 1 || res.Skipped[0] != "notify" {
		t.Errorf("skipped = %v", res.Skipped)
	}
	for _, e := range batch[:2] {
		if _, ok := entryTagRows(t, st, e.ID)[tag.ID]; !ok {
			t.Errorf("entry %d missing tag after set_priority changed the match", e.ID)
		}
	}
	// Re-applying changes nothing.
	res, err = st.ApplyRuleHistorical(ctx, rule)
	if err != nil || res.Affected != 0 {
		t.Errorf("second apply = %+v, %v", res, err)
	}
}

// Structured numbers compare as text the way Postgres's ->> renders them.
func TestStructuredNumberParity(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	e := store.Entry{ReceivedAt: time.Now(), Host: "h", Msg: "m", Status: "new",
		Structured: []byte(`{"bytes": 1000000, "ratio": 0.25, "neg": -3, "ok": true}`)}
	batch := []store.Entry{e}
	if err := st.InsertEntries(ctx, batch); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"bytes", "ratio", "neg", "ok"} {
		var sqlText string
		if err := st.Pool.QueryRow(ctx, `SELECT structured->>$1 FROM entries WHERE id = $2`, key, batch[0].ID).Scan(&sqlText); err != nil {
			t.Fatal(err)
		}
		got, ok := e.FieldValue("structured." + key)
		if !ok || got != sqlText {
			t.Errorf("structured.%s: in-memory %v, SQL %q", key, got, sqlText)
		}
		cond := rules.Cond{Field: "structured." + key, Op: "eq", Value: sqlText}
		list, err := st.ListEntries(ctx, store.EntryFilter{Cond: cond, IncludeSuppressed: true})
		if err != nil {
			t.Fatal(err)
		}
		if (len(list) == 1) != cond.Match(&e) {
			t.Errorf("structured.%s eq %q: SQL matched %d, memory %v", key, sqlText, len(list), cond.Match(&e))
		}
	}
}

// On a fresh database the planner estimate is 0 (or -1) until the table is
// analyzed; small tables are counted exactly instead (#64).
func TestGetStatsCountsSmallTablesExactly(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	got, err := st.GetStats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.ApproxTotal != 0 || !got.TotalExact {
		t.Fatalf("empty table: %+v", got)
	}
	batch := []store.Entry{
		{ReceivedAt: time.Now(), Host: "h", Msg: "one", Status: "new"},
		{ReceivedAt: time.Now(), Host: "h", Msg: "two", Status: "new"},
		{ReceivedAt: time.Now(), Host: "h", Msg: "three", Status: "new"},
	}
	if err := st.InsertEntries(ctx, batch); err != nil {
		t.Fatal(err)
	}
	if got, err = st.GetStats(ctx); err != nil {
		t.Fatal(err)
	}
	if got.ApproxTotal != 3 || !got.TotalExact || got.LastMinute != 3 {
		t.Fatalf("three rows: %+v", got)
	}

	// Past the bound the count stops and the result is an estimate again,
	// never below what was counted.
	if _, err := st.Pool.Exec(ctx, `INSERT INTO entries (host, msg) SELECT 'h', 'bulk' FROM generate_series(1, 10001)`); err != nil {
		t.Fatal(err)
	}
	if got, err = st.GetStats(ctx); err != nil {
		t.Fatal(err)
	}
	if got.ApproxTotal < 10001 || got.TotalExact {
		t.Fatalf("large table: %+v", got)
	}
}
