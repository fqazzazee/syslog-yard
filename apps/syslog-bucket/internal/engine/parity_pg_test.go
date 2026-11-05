package engine_test

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"
	"time"

	"github.com/syslog-yard/syslog-bucket/internal/engine"
	"github.com/syslog-yard/syslog-bucket/internal/rules"
	"github.com/syslog-yard/syslog-bucket/internal/store"
	"github.com/syslog-yard/syslog-bucket/internal/store/storetest"
)

// The rule engine has two halves that must agree: ingest-time evaluation
// (engine.Apply, Cond.Match in memory) and apply-to-history (CompileSQL,
// store.ApplyRuleHistorical in Postgres). These tests run both over the
// same fixtures and compare the outcome.

var (
	hosts    = []string{"fw-01", "FW-02", "db_1", "web%1", `core\sw`, ""}
	apps     = []string{"sshd", "kernel", "FortiGate", "cron", ""}
	classes  = []string{"firewall", "host", "network", ""}
	statuses = []string{"new", "ack", "closed"}
	msgs     = []string{
		"Failed password for root from 10.0.0.1 port 22",
		"Accepted publickey for alice from 10.0.0.9",
		"user=bob action=blocked dst=192.0.2.7",
		"disk 95% full on /var",
		"link down on port_7",
		"PLC mode change detected",
		"",
	}
	structureds = []string{
		`{"action":"blocked","user":"Alice"}`,
		`{"action":"allowed","bytes":1000}`,
		`{"user":"bob","ratio":0.5,"ok":true}`,
		`{}`,
		`{"action":null}`,
	}
	mitres = [][]string{nil, {"T1110"}, {"T1110", "T1078"}, {"T1190"}}
	ots    = [][]string{nil, {"CL-KT"}, {"CL-KT", "CL-CHG"}}
)

type fixture struct {
	st      *store.Store
	tags    []int64
	sources []int64
	now     time.Time
}

// newFixture fills a database with entries covering every field, NULLs and
// missing structured keys included. The same seed yields the same rows, ids
// and tag ids in any fresh database.
func newFixture(t *testing.T, seed uint64, n int) fixture {
	t.Helper()
	st := storetest.New(t)
	ctx := context.Background()
	f := fixture{st: st, now: time.Now()}
	for i := range 3 {
		tag, err := st.CreateTag(ctx, store.Tag{Name: fmt.Sprint("tag", i)})
		if err != nil {
			t.Fatal(err)
		}
		f.tags = append(f.tags, tag.ID)
	}
	for i := range 2 {
		id, err := st.UpsertSource(ctx, fmt.Sprint("src", i), fmt.Sprint("192.0.2.", i+1))
		if err != nil {
			t.Fatal(err)
		}
		f.sources = append(f.sources, id)
	}
	if err := st.InsertEntries(ctx, f.entries(seed, n)); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f fixture) entries(seed uint64, n int) []store.Entry {
	r := rand.New(rand.NewPCG(seed, 99))
	ages := []time.Duration{10 * time.Second, 2 * time.Hour, 48 * time.Hour}
	out := make([]store.Entry, n)
	for i := range out {
		e := store.Entry{
			ReceivedAt:  f.now.Add(-ages[r.IntN(len(ages))]),
			Host:        pick(r, hosts),
			AppName:     pick(r, apps),
			DeviceClass: pick(r, classes),
			Status:      pick(r, statuses),
			Msg:         pick(r, msgs),
			Structured:  json.RawMessage(pick(r, structureds)),
			Severity:    int16(r.IntN(8)),
			Priority:    int16(r.IntN(4)),
			Suppressed:  r.IntN(5) == 0,
			Mitre:       slices.Clone(pick(r, mitres)),
			OT:          slices.Clone(pick(r, ots)),
		}
		if r.IntN(2) == 0 {
			fac := int16(r.IntN(24))
			e.Facility = &fac
		}
		if r.IntN(3) > 0 {
			src := pick(r, f.sources)
			e.SourceID = &src
		}
		if r.IntN(3) == 0 {
			// A manual tag: stored with a NULL rule id.
			tag := pick(r, f.tags)
			e.TagIDs = []int64{tag}
			e.RuleTags = []store.RuleTag{{TagID: tag}}
		}
		out[i] = e
	}
	return out
}

func pick[T any](r *rand.Rand, xs []T) T { return xs[r.IntN(len(xs))] }

// all reads every stored entry back, in id order.
func (f fixture) all(t *testing.T) []store.Entry {
	t.Helper()
	got, err := f.st.ListEntries(context.Background(), store.EntryFilter{IncludeSuppressed: true, Sort: "time", Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	slices.Reverse(got)
	return got
}

// condGen builds random valid condition trees over the fixture vocabulary.
type condGen struct {
	r    *rand.Rand
	f    fixture
	tags []int64
}

var (
	strFields = []string{"host", "app_name", "device_class", "msg", "status",
		"structured.action", "structured.user", "structured.bytes", "structured.ratio", "structured.ok", "structured.missing"}
	numFields = []string{"severity", "facility", "priority", "source_id"}
	strOps    = []string{"eq", "ne", "contains", "prefix"}
	ordOps    = []string{"eq", "ne", "lt", "lte", "gt", "gte"}
	strVals   = []string{"fw", "FW-0", "fw-01", "db_", "db_1", "web%", "web%1", `core\`, `core\sw`, "%", "_", "",
		"sshd", "SSHD", "fortigate", "Forti", "firewall", "host", "new", "ACK", "blocked", "alice", "bob",
		"password", "Failed", "95%", "port_7", "1000", "0.5", "true", "allowed"}
	textQueries = []string{"password", "alice", `"failed password"`, "-root password", "blocked or down",
		"disk", "10.0.0.1", "port", "plc mode", "nothing-here"}
)

func (g condGen) cond(depth int) rules.Cond {
	if depth > 0 && g.r.IntN(3) == 0 {
		n := 1 + g.r.IntN(3)
		subs := make([]rules.Cond, n)
		for i := range subs {
			subs[i] = g.cond(depth - 1)
		}
		switch g.r.IntN(3) {
		case 0:
			return rules.Cond{All: subs}
		case 1:
			return rules.Cond{Any: subs}
		default:
			return rules.Cond{Not: &subs[0]}
		}
	}
	switch g.r.IntN(10) {
	case 0, 1, 2:
		return rules.Cond{Field: pick(g.r, strFields), Op: pick(g.r, strOps), Value: pick(g.r, strVals)}
	case 3, 4:
		field := pick(g.r, numFields)
		var v any = float64(g.r.IntN(10) - 1)
		switch {
		case field == "source_id" && g.r.IntN(2) == 0:
			v = float64(pick(g.r, g.f.sources))
		case g.r.IntN(4) == 0:
			// Fractional, out of smallint range, or a numeric string.
			v = pick(g.r, []any{2.5, -0.5, 7.999, 40000.0, "3", "1.5", "NaN"})
		}
		return rules.Cond{Field: field, Op: pick(g.r, ordOps), Value: v}
	case 5:
		ago := []time.Duration{time.Minute, 3 * time.Hour, 72 * time.Hour}
		at := g.f.now.Add(-pick(g.r, ago)).UTC().Format(time.RFC3339)
		return rules.Cond{Field: "received_at", Op: pick(g.r, ordOps), Value: at}
	case 6:
		return rules.Cond{Text: pick(g.r, textQueries)}
	case 7:
		return rules.Cond{TagID: pick(g.r, g.tags)}
	case 8:
		if g.r.IntN(2) == 0 {
			return rules.Cond{Mitre: pick(g.r, []string{"T1110", "T1078", "T1190", "T9999"})}
		}
		return rules.Cond{OT: pick(g.r, []string{"CL-KT", "CL-CHG", "CL-XX"})}
	default:
		return rules.Cond{LastSeconds: pick(g.r, []int64{60, 5 * 3600, 7 * 86400})}
	}
}

// matchIDs evaluates c both ways over the fixture.
func matchIDs(t *testing.T, f fixture, entries []store.Entry, c rules.Cond) (mem, sql []int64) {
	t.Helper()
	for i := range entries {
		if c.Match(&entries[i]) {
			mem = append(mem, entries[i].ID)
		}
	}
	got, err := f.st.ListEntries(context.Background(), store.EntryFilter{Cond: c, IncludeSuppressed: true, Limit: 1000})
	if err != nil {
		t.Fatalf("SQL for %s: %v", condJSON(c), err)
	}
	for _, e := range got {
		sql = append(sql, e.ID)
	}
	slices.Sort(sql)
	return mem, sql
}

func condJSON(c rules.Cond) string {
	b, _ := json.Marshal(c)
	return string(b)
}

// Shared fixtures through hand-picked conditions, including the NULL and
// LIKE-escaping corners.
func TestCondParityFixtures(t *testing.T) {
	f := newFixture(t, 1, 120)
	entries := f.all(t)
	nine := float64(9)
	cases := []rules.Cond{
		{},
		{Field: "host", Op: "eq", Value: "fw-02"},
		{Field: "host", Op: "contains", Value: "%"},
		{Field: "host", Op: "prefix", Value: "db_"},
		{Field: "host", Op: "contains", Value: `\`},
		{Field: "host", Op: "eq", Value: ""},
		{Field: "app_name", Op: "ne", Value: "SSHD"},
		{Field: "msg", Op: "contains", Value: "95%"},
		{Field: "structured.action", Op: "eq", Value: "blocked"},
		{Field: "structured.action", Op: "ne", Value: "blocked"},
		{Field: "structured.bytes", Op: "eq", Value: "1000"},
		{Field: "structured.ok", Op: "eq", Value: "true"},
		{Field: "structured.missing", Op: "ne", Value: "x"},
		{Not: &rules.Cond{Field: "structured.action", Op: "eq", Value: "blocked"}},
		{Not: &rules.Cond{Field: "structured.user", Op: "contains", Value: "o"}},
		{Field: "facility", Op: "lt", Value: nine},
		{Not: &rules.Cond{Field: "facility", Op: "lt", Value: nine}},
		{Field: "facility", Op: "ne", Value: nine},
		{Not: &rules.Cond{Field: "source_id", Op: "eq", Value: float64(f.sources[0])}},
		{Not: &rules.Cond{Any: []rules.Cond{
			{Field: "facility", Op: "gte", Value: float64(4)},
			{Field: "structured.user", Op: "eq", Value: "alice"},
		}}},
		{Field: "severity", Op: "lte", Value: float64(3)},
		{Field: "severity", Op: "lt", Value: 2.5},
		{Field: "priority", Op: "gt", Value: "1.5"},
		{Field: "facility", Op: "ne", Value: 40000.0},
		{Field: "received_at", Op: "gte", Value: f.now.Add(-3 * time.Hour).UTC().Format(time.RFC3339)},
		{LastSeconds: 3600},
		{Not: &rules.Cond{LastSeconds: 3600}},
		{Text: `"failed password" or alice`},
		{TagID: f.tags[0]},
		{Not: &rules.Cond{TagID: f.tags[1]}},
		{Mitre: "T1078"},
		{OT: "CL-CHG"},
	}
	for _, c := range cases {
		if mem, sql := matchIDs(t, f, entries, c); !slices.Equal(mem, sql) {
			t.Errorf("%s:\n memory %v\n    SQL %v", condJSON(c), mem, sql)
		}
	}
}

// Random condition trees, fixed seed: any disagreement between Match and
// CompileSQL is a bug in one of them.
func TestCondParityRandom(t *testing.T) {
	f := newFixture(t, 2, 200)
	entries := f.all(t)
	g := condGen{r: rand.New(rand.NewPCG(58, 2026)), f: f, tags: f.tags}
	failures := 0
	for i := range 600 {
		c := g.cond(3)
		if err := c.Validate(); err != nil {
			t.Fatalf("generator produced an invalid tree %s: %v", condJSON(c), err)
		}
		if mem, sql := matchIDs(t, f, entries, c); !slices.Equal(mem, sql) {
			t.Errorf("case %d %s:\n memory %v\n    SQL %v", i, condJSON(c), mem, sql)
			if failures++; failures > 10 {
				t.Fatal("too many mismatches")
			}
		}
	}
}

// outcome is what a rule run can change on an entry.
type outcome struct {
	Priority   int16
	Suppressed bool
	Tags       map[int64]int64 // tag → rule id (0 = manual)
	Mitre, OT  []string
}

func outcomes(t *testing.T, st *store.Store) map[int64]outcome {
	t.Helper()
	ctx := context.Background()
	out := map[int64]outcome{}
	rows, err := st.Pool.Query(ctx, `SELECT id, priority, suppressed, mitre, ot FROM entries`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var id int64
		var o outcome
		if err := rows.Scan(&id, &o.Priority, &o.Suppressed, &o.Mitre, &o.OT); err != nil {
			t.Fatal(err)
		}
		slices.Sort(o.Mitre)
		slices.Sort(o.OT)
		o.Tags = map[int64]int64{}
		out[id] = o
	}
	rows.Close()
	rows, err = st.Pool.Query(ctx, `SELECT entry_id, tag_id, COALESCE(rule_id, 0) FROM entry_tags`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var e, tag, rule int64
		if err := rows.Scan(&e, &tag, &rule); err != nil {
			t.Fatal(err)
		}
		out[e].Tags[tag] = rule
	}
	return out
}

func diffOutcomes(t *testing.T, label string, ingest, hist map[int64]outcome) {
	t.Helper()
	if len(ingest) != len(hist) {
		t.Fatalf("%s: %d entries at ingest, %d in history", label, len(ingest), len(hist))
	}
	bad := 0
	for id, a := range ingest {
		b := hist[id]
		if a.Priority != b.Priority || a.Suppressed != b.Suppressed || !slices.Equal(a.Mitre, b.Mitre) ||
			!slices.Equal(a.OT, b.OT) || fmt.Sprint(a.Tags) != fmt.Sprint(b.Tags) {
			t.Errorf("%s: entry %d\n ingest  %+v\n history %+v", label, id, a, b)
			if bad++; bad > 5 {
				t.FailNow()
			}
		}
	}
}

// runBoth applies the same rule set at ingest (engine over fresh entries) and
// to history (ApplyRuleHistorical, one rule at a time in position order) and
// compares every entry. Rules only change the entry they fire on, so running
// them rule-by-rule over history equals running them entry-by-entry at
// ingest.
func runBoth(t *testing.T, label string, seed uint64, n int, mkRules func(f fixture) []store.Rule) {
	t.Helper()
	ctx := context.Background()

	// History: raw entries stored first, rules applied afterwards.
	hist := newFixture(t, seed, n)
	ruleSet := mkRules(hist)
	for i := range ruleSet {
		ruleSet[i].Position = i
		ruleSet[i].Enabled = true
		created, err := hist.st.CreateRule(ctx, ruleSet[i])
		if err != nil {
			t.Fatal(err)
		}
		ruleSet[i] = created
	}
	stored, err := hist.st.ListRules(ctx) // the JSON round trip the API does
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range stored {
		if _, err := hist.st.ApplyRuleHistorical(ctx, r); err != nil {
			t.Fatalf("%s: apply rule %d %s: %v", label, r.ID, condJSON(r.Condition), err)
		}
	}

	// Ingest: the same rules (same ids in a fresh database) loaded into the
	// engine, entries evaluated before insert.
	ing := storetest.New(t)
	for i := range 3 {
		if _, err := ing.CreateTag(ctx, store.Tag{Name: fmt.Sprint("tag", i)}); err != nil {
			t.Fatal(err)
		}
	}
	for i := range 2 {
		if _, err := ing.UpsertSource(ctx, fmt.Sprint("src", i), fmt.Sprint("192.0.2.", i+1)); err != nil {
			t.Fatal(err)
		}
	}
	for _, r := range ruleSet {
		created, err := ing.CreateRule(ctx, r)
		if err != nil || created.ID != r.ID {
			t.Fatalf("rule ids diverged: %d vs %d (%v)", created.ID, r.ID, err)
		}
	}
	eng := engine.New(ing)
	if err := eng.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	ingFix := hist
	ingFix.st = ing
	batch := ingFix.entries(seed, n)
	for i := range batch {
		// Entries reach the engine as they'll be stored: Postgres keeps
		// microseconds.
		batch[i].ReceivedAt = batch[i].ReceivedAt.Truncate(time.Microsecond)
		eng.Apply(&batch[i])
	}
	if err := ing.InsertEntries(ctx, batch); err != nil {
		t.Fatal(err)
	}
	diffOutcomes(t, label, outcomes(t, ing), outcomes(t, hist.st))
}

func TestRuleParityFixtures(t *testing.T) {
	runBoth(t, "fixtures", 3, 150, func(f fixture) []store.Rule {
		return []store.Rule{
			{Name: "brute force", Condition: rules.Cond{All: []rules.Cond{
				{Text: `"failed password"`}, {Field: "severity", Op: "lte", Value: float64(5)},
			}}, Actions: []rules.Action{{Type: "tag", TagID: f.tags[0]}, {Type: "set_priority", Priority: 3}, {Type: "set_mitre", Mitre: []string{"T1110", "T1021"}}}},
			// Sees the previous rule's priority, at ingest and in history.
			{Name: "escalated", Condition: rules.Cond{Field: "priority", Op: "eq", Value: float64(3)},
				Actions: []rules.Action{{Type: "tag", TagID: f.tags[1]}}},
			{Name: "noise", Condition: rules.Cond{Not: &rules.Cond{Field: "facility", Op: "lt", Value: float64(12)}},
				Actions: []rules.Action{{Type: "suppress"}, {Type: "notify", ChannelID: 0}}},
			{Name: "no user", Condition: rules.Cond{Not: &rules.Cond{Field: "structured.user", Op: "eq", Value: "bob"}},
				Actions: []rules.Action{{Type: "set_ot", OT: []string{"CL-KT", "CL-NEW"}}, {Type: "set_priority", Priority: 1}}},
			{Name: "tagged", Condition: rules.Cond{TagID: f.tags[2]},
				Actions: []rules.Action{{Type: "tag", TagID: f.tags[2]}, {Type: "set_priority", Priority: 2}}},
		}
	})
}

func TestRuleParityRandom(t *testing.T) {
	const runs = 6
	r := rand.New(rand.NewPCG(59, 2026))
	for run := range runs {
		runBoth(t, fmt.Sprint("run ", run), uint64(100+run), 120, func(f fixture) []store.Rule {
			g := condGen{r: r, f: f, tags: f.tags}
			var out []store.Rule
			for i := range 1 + r.IntN(4) {
				var actions []rules.Action
				for range 1 + r.IntN(3) {
					switch r.IntN(5) {
					case 0:
						actions = append(actions, rules.Action{Type: "tag", TagID: pick(r, f.tags)})
					case 1:
						actions = append(actions, rules.Action{Type: "set_priority", Priority: int16(r.IntN(4))})
					case 2:
						actions = append(actions, rules.Action{Type: "suppress"})
					case 3:
						actions = append(actions, rules.Action{Type: "set_mitre", Mitre: []string{pick(r, []string{"T1110", "T1046", "T1078"})}})
					default:
						actions = append(actions, rules.Action{Type: "set_ot", OT: []string{pick(r, []string{"CL-KT", "CL-SCAN"})}})
					}
				}
				out = append(out, store.Rule{Name: fmt.Sprint("r", i), Condition: g.cond(2), Actions: actions})
			}
			return out
		})
	}
}
