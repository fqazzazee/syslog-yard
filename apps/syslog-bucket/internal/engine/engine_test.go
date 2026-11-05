package engine

import (
	"slices"
	"testing"

	"github.com/syslog-yard/syslog-bucket/internal/rules"
	"github.com/syslog-yard/syslog-bucket/internal/store"
)

func withRules(rs ...store.Rule) *Engine {
	return &Engine{rules: rs}
}

// Rules run in order against the entry as earlier rules left it: tags
// accumulate once each with attribution, the last priority wins, and
// notifications queue without touching the entry otherwise.
func TestApplyActionsInOrder(t *testing.T) {
	sshd := rules.Cond{Field: "app_name", Op: "eq", Value: "sshd"}
	g := withRules(
		store.Rule{ID: 1, Condition: sshd, Actions: []rules.Action{
			{Type: "tag", TagID: 10}, {Type: "set_priority", Priority: 1}, {Type: "set_mitre", Mitre: []string{"T1110", "T1078"}},
		}},
		// Sees rule 1's priority.
		store.Rule{ID: 2, Condition: rules.Cond{Field: "priority", Op: "eq", Value: float64(1)}, Actions: []rules.Action{
			{Type: "tag", TagID: 10}, {Type: "tag", TagID: 11}, {Type: "set_priority", Priority: 3},
			{Type: "set_mitre", Mitre: []string{"T1078", "T1021"}}, {Type: "set_ot", OT: []string{"CL-KT"}},
			{Type: "notify", ChannelID: 5},
		}},
		store.Rule{ID: 3, Condition: rules.Cond{Field: "host", Op: "eq", Value: "other"}, Actions: []rules.Action{
			{Type: "suppress"},
		}},
	)
	e := store.Entry{AppName: "sshd", Host: "h", TagIDs: []int64{11}, Mitre: []string{"T1110"}}
	g.Apply(&e)

	if !slices.Equal(e.TagIDs, []int64{11, 10}) {
		t.Errorf("TagIDs = %v, want [11 10]", e.TagIDs)
	}
	if want := []store.RuleTag{{TagID: 10, RuleID: 1}}; !slices.Equal(e.RuleTags, want) {
		t.Errorf("RuleTags = %v, want %v (11 was already there, 10 only once)", e.RuleTags, want)
	}
	if e.Priority != 3 {
		t.Errorf("Priority = %d, want 3 (later rule wins)", e.Priority)
	}
	if !slices.Equal(e.Mitre, []string{"T1110", "T1078", "T1021"}) {
		t.Errorf("Mitre = %v", e.Mitre)
	}
	if !slices.Equal(e.OT, []string{"CL-KT"}) {
		t.Errorf("OT = %v", e.OT)
	}
	if want := []store.Notify{{ChannelID: 5, RuleID: 2}}; !slices.Equal(e.Notifies, want) {
		t.Errorf("Notifies = %v, want %v", e.Notifies, want)
	}
	if e.Suppressed {
		t.Error("non-matching rule suppressed the entry")
	}
}

func TestApplyNoRules(t *testing.T) {
	e := store.Entry{AppName: "sshd", Priority: 2}
	New(nil).Apply(&e)
	if e.Priority != 2 || e.Suppressed || len(e.TagIDs) != 0 {
		t.Errorf("entry changed with no rules: %+v", e)
	}
}

func TestAppendUnique(t *testing.T) {
	got := appendUnique([]string{"a"}, []string{"b", "a", "b", "c"})
	if !slices.Equal(got, []string{"a", "b", "c"}) {
		t.Errorf("appendUnique = %v", got)
	}
}
