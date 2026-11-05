package store_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/syslog-yard/syslog-bucket/internal/rules"
	"github.com/syslog-yard/syslog-bucket/internal/store"
	"github.com/syslog-yard/syslog-bucket/internal/store/storetest"
)

// insert stores a batch and fails the test on error.
func insert(t *testing.T, st *store.Store, batch []store.Entry) []store.Entry {
	t.Helper()
	if err := st.InsertEntries(context.Background(), batch); err != nil {
		t.Fatalf("insert: %v", err)
	}
	return batch
}

func ids(list []store.Entry) []int64 {
	out := make([]int64, len(list))
	for i, e := range list {
		out[i] = e.ID
	}
	return out
}

func list(t *testing.T, st *store.Store, f store.EntryFilter) []store.Entry {
	t.Helper()
	got, err := st.ListEntries(context.Background(), f)
	if err != nil {
		t.Fatalf("list %+v: %v", f, err)
	}
	return got
}

// Each entry's id must point at that entry's row, whatever the batch size,
// and ids must ascend in batch order (the time sort pages on id).
func TestInsertEntriesIDsMatchRows(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	for _, n := range []int{1, 2, 37, 500} {
		now := time.Now()
		batch := make([]store.Entry, n)
		for i := range batch {
			batch[i] = store.Entry{
				ReceivedAt: now, // equal timestamps: nothing but the id tells them apart
				Host:       fmt.Sprintf("h%d", i%7),
				Msg:        fmt.Sprintf("batch %d row %d", n, i),
				Severity:   int16(i % 8),
				Status:     "new",
				Mitre:      []string{fmt.Sprintf("T%04d", i)},
			}
		}
		insert(t, st, batch)
		for i := range batch {
			if i > 0 && batch[i].ID <= batch[i-1].ID {
				t.Fatalf("n=%d: ids not ascending in batch order: %d then %d", n, batch[i-1].ID, batch[i].ID)
			}
			var msg string
			var mitre []string
			if err := st.Pool.QueryRow(ctx, `SELECT msg, mitre FROM entries WHERE id = $1`, batch[i].ID).Scan(&msg, &mitre); err != nil {
				t.Fatalf("n=%d row %d: %v", n, i, err)
			}
			if msg != batch[i].Msg || len(mitre) != 1 || mitre[0] != batch[i].Mitre[0] {
				t.Fatalf("n=%d: id %d holds %q %v, want %q %v", n, batch[i].ID, msg, mitre, batch[i].Msg, batch[i].Mitre)
			}
		}
	}
	// Rule tags land on the row they were computed for.
	tag, _ := st.CreateTag(ctx, store.Tag{Name: "t"})
	batch := make([]store.Entry, 20)
	for i := range batch {
		batch[i] = store.Entry{ReceivedAt: time.Now(), Msg: fmt.Sprint(i), Status: "new"}
		if i%3 == 0 {
			batch[i].TagIDs = []int64{tag.ID}
			batch[i].RuleTags = []store.RuleTag{{TagID: tag.ID}}
		}
	}
	insert(t, st, batch)
	got := list(t, st, store.EntryFilter{Cond: rules.Cond{TagID: tag.ID}, Limit: 100})
	var msgs []string
	for _, e := range got {
		msgs = append(msgs, e.Msg)
	}
	slices.Sort(msgs)
	if want := []string{"0", "12", "15", "18", "3", "6", "9"}; !slices.Equal(msgs, want) {
		t.Errorf("tagged entries %v, want %v", msgs, want)
	}
}

// Concurrent batches must not cross ids even when they interleave.
func TestInsertEntriesConcurrentBatches(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	const workers, per = 8, 60
	errs := make(chan error, workers)
	batches := make([][]store.Entry, workers)
	for w := range workers {
		batches[w] = make([]store.Entry, per)
		for i := range batches[w] {
			batches[w][i] = store.Entry{ReceivedAt: time.Now(), Host: fmt.Sprint("w", w), Msg: fmt.Sprintf("%d/%d", w, i), Status: "new"}
		}
		go func() { errs <- st.InsertEntries(ctx, batches[w]) }()
	}
	for range workers {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
	for _, b := range batches {
		for _, e := range b {
			var msg string
			if err := st.Pool.QueryRow(ctx, `SELECT msg FROM entries WHERE id = $1`, e.ID).Scan(&msg); err != nil || msg != e.Msg {
				t.Fatalf("id %d holds %q (%v), want %q", e.ID, msg, err, e.Msg)
			}
		}
	}
}

// Paging backwards with BeforeID visits every visible entry exactly once,
// newest first, even when all of them share one received_at.
func TestListEntriesTimePagination(t *testing.T) {
	st := storetest.New(t)
	same := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	batch := make([]store.Entry, 53)
	for i := range batch {
		batch[i] = store.Entry{ReceivedAt: same, Host: "h", Msg: fmt.Sprint(i), Status: "new", Suppressed: i%10 == 9}
	}
	insert(t, st, batch)
	var want []int64
	for i := len(batch) - 1; i >= 0; i-- {
		if !batch[i].Suppressed {
			want = append(want, batch[i].ID)
		}
	}

	var got []int64
	var before *int64
	for pages := 0; ; pages++ {
		if pages > 20 {
			t.Fatal("pagination does not terminate")
		}
		page := list(t, st, store.EntryFilter{BeforeID: before, Limit: 7})
		if len(page) == 0 {
			break
		}
		if len(page) > 7 {
			t.Fatalf("page of %d exceeds limit", len(page))
		}
		got = append(got, ids(page)...)
		last := page[len(page)-1].ID
		before = &last
	}
	if !slices.Equal(got, want) {
		t.Errorf("paged ids\n got %v\nwant %v", got, want)
	}

	// AfterID fetches newer entries in ascending order.
	after := want[10]
	newer := list(t, st, store.EntryFilter{AfterID: &after, Limit: 4})
	wantNewer := []int64{want[9], want[8], want[7], want[6]}
	if !slices.Equal(ids(newer), wantNewer) {
		t.Errorf("after %d: got %v, want %v", after, ids(newer), wantNewer)
	}

	// Entries arriving mid-scroll don't shift the cursor.
	before = &want[20]
	first := list(t, st, store.EntryFilter{BeforeID: before, Limit: 5})
	insert(t, st, []store.Entry{{ReceivedAt: same, Host: "h", Msg: "late", Status: "new"}})
	again := list(t, st, store.EntryFilter{BeforeID: before, Limit: 5})
	if !slices.Equal(ids(first), ids(again)) {
		t.Errorf("cursor moved after a new insert: %v then %v", ids(first), ids(again))
	}

	// Suppressed entries come back only on request.
	all := list(t, st, store.EntryFilter{IncludeSuppressed: true, Limit: 1000})
	if len(all) != len(batch)+1 {
		t.Errorf("include_suppressed returned %d, want %d", len(all), len(batch)+1)
	}
}

func TestListEntriesLimitClamp(t *testing.T) {
	st := storetest.New(t)
	batch := make([]store.Entry, 1100)
	for i := range batch {
		batch[i] = store.Entry{ReceivedAt: time.Now(), Status: "new"}
	}
	insert(t, st, batch[:550])
	insert(t, st, batch[550:])
	if n := len(list(t, st, store.EntryFilter{})); n != 100 {
		t.Errorf("default limit returned %d, want 100", n)
	}
	if n := len(list(t, st, store.EntryFilter{Limit: 5000})); n != 1000 {
		t.Errorf("limit 5000 returned %d, want the 1000 cap", n)
	}
}

// Every column sort orders by its key in the requested direction and breaks
// ties by newest id first, so the ranking is deterministic.
func TestListEntriesSortColumns(t *testing.T) {
	st := storetest.New(t)
	hosts := []string{"beta", "Alpha", "gamma", "alpha", "Beta"}
	apps := []string{"sshd", "Kernel", "cron", "kernel", "SSHD"}
	classes := []string{"firewall", "host", "", "network", "host"}
	var batch []store.Entry
	for i := range 40 {
		batch = append(batch, store.Entry{
			ReceivedAt:  time.Now(),
			Host:        hosts[i%len(hosts)],
			AppName:     apps[(i/2)%len(apps)],
			DeviceClass: classes[(i/3)%len(classes)],
			Severity:    int16(i % 8),
			Priority:    int16((i * 7) % 4),
			Msg:         fmt.Sprint(i),
			Status:      "new",
		})
	}
	insert(t, st, batch)

	key := map[string]func(e store.Entry) string{
		"severity":     func(e store.Entry) string { return fmt.Sprintf("%03d", e.Severity) },
		"priority":     func(e store.Entry) string { return fmt.Sprintf("%03d", e.Priority) },
		"host":         func(e store.Entry) string { return strings.ToLower(e.Host) },
		"app":          func(e store.Entry) string { return strings.ToLower(e.AppName) },
		"device_class": func(e store.Entry) string { return e.DeviceClass },
	}
	for col, k := range key {
		for _, desc := range []bool{false, true} {
			want := slices.Clone(batch)
			slices.SortFunc(want, func(a, b store.Entry) int {
				c := strings.Compare(k(a), k(b))
				if desc {
					c = -c
				}
				if c != 0 {
					return c
				}
				return int(b.ID - a.ID) // ties: newest first
			})
			got := list(t, st, store.EntryFilter{Sort: col, Desc: desc, Limit: 1000})
			if !slices.Equal(ids(got), ids(want)) {
				t.Errorf("sort %s desc=%v\n got %v\nwant %v", col, desc, ids(got), ids(want))
			}
			// A narrower limit returns a prefix of the same ranking.
			top := list(t, st, store.EntryFilter{Sort: col, Desc: desc, Limit: 9})
			if !slices.Equal(ids(top), ids(want[:9])) {
				t.Errorf("sort %s desc=%v limit 9: %v, want %v", col, desc, ids(top), ids(want[:9]))
			}
		}
	}
	for _, s := range []string{"", "time"} {
		got := list(t, st, store.EntryFilter{Sort: s, Limit: 1000})
		if !slices.IsSortedFunc(got, func(a, b store.Entry) int { return int(b.ID - a.ID) }) || len(got) != len(batch) {
			t.Errorf("sort %q is not newest-first over every entry", s)
		}
	}
	if _, err := st.ListEntries(context.Background(), store.EntryFilter{Sort: "msg; DROP TABLE entries"}); err == nil {
		t.Error("unknown sort column accepted")
	}
}

// ListEntries round-trips every column InsertEntries writes.
func TestListEntriesRoundTrip(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	src, err := st.UpsertSource(ctx, "fw1", "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	fac := int16(4)
	dev := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	in := store.Entry{
		ReceivedAt: time.Date(2026, 3, 4, 5, 6, 8, 123000, time.UTC), DeviceTime: &dev,
		SourceID: &src, Facility: &fac, Severity: 2, AppName: "app", Host: "fw1", Msg: "m",
		Structured: []byte(`{"k":"v"}`), Priority: 3, Status: "ack", Suppressed: true,
		DeviceClass: "firewall", Mitre: []string{"T1110"}, OT: []string{"CL-KT"},
	}
	batch := insert(t, st, []store.Entry{in})
	got, err := st.GetEntry(ctx, batch[0].ID)
	if err != nil || got == nil {
		t.Fatalf("get: %v %v", got, err)
	}
	if !got.ReceivedAt.Equal(in.ReceivedAt) || !got.DeviceTime.Equal(dev) || *got.SourceID != src ||
		got.SourceIP != "192.0.2.1" || *got.Facility != fac || got.Severity != 2 || got.AppName != "app" ||
		got.Host != "fw1" || got.Msg != "m" || string(got.Structured) != `{"k": "v"}` || got.Priority != 3 ||
		got.Status != "ack" || !got.Suppressed || got.DeviceClass != "firewall" ||
		!slices.Equal(got.Mitre, in.Mitre) || !slices.Equal(got.OT, in.OT) || len(got.TagIDs) != 0 {
		t.Errorf("round trip mismatch:\n got %+v\nwant %+v", *got, in)
	}
	if missing, err := st.GetEntry(ctx, batch[0].ID+1000); err != nil || missing != nil {
		t.Errorf("GetEntry of an unknown id = %v, %v", missing, err)
	}
}
