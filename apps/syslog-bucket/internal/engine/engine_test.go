package engine

import (
	"testing"

	"github.com/syslog-yard/syslog-bucket/internal/rules"
	"github.com/syslog-yard/syslog-bucket/internal/store"
)

func rule(id int64, actions ...rules.Action) store.Rule {
	return store.Rule{ID: id, Enabled: true,
		Condition: rules.Cond{Field: "host", Op: "eq", Value: "fw1"}, Actions: actions}
}

var (
	notify   = rules.Action{Type: "notify", ChannelID: 7}
	suppress = rules.Action{Type: "suppress"}
)

func TestSuppressCancelsNotify(t *testing.T) {
	for name, rs := range map[string][]store.Rule{
		"same rule, notify first":   {rule(1, notify, suppress)},
		"same rule, suppress first": {rule(1, suppress, notify)},
		"earlier rule notifies":     {rule(1, notify), rule(2, suppress)},
		"later rule notifies":       {rule(1, suppress), rule(2, notify)},
	} {
		g := &Engine{rules: rs}
		e := store.Entry{Host: "fw1"}
		g.Apply(&e)
		if !e.Suppressed {
			t.Errorf("%s: entry not suppressed", name)
		}
		if len(e.Notifies) != 0 {
			t.Errorf("%s: suppressed entry still queues %v", name, e.Notifies)
		}
	}
}

func TestNotifyWithoutSuppress(t *testing.T) {
	g := &Engine{rules: []store.Rule{
		rule(1, notify),
		rule(2, rules.Action{Type: "set_priority", Priority: 3}),
		// A suppress rule that doesn't match this entry changes nothing.
		{ID: 3, Enabled: true, Condition: rules.Cond{Field: "host", Op: "eq", Value: "other"}, Actions: []rules.Action{suppress}},
	}}
	e := store.Entry{Host: "fw1"}
	g.Apply(&e)
	if e.Suppressed || len(e.Notifies) != 1 || e.Notifies[0] != (store.Notify{ChannelID: 7, RuleID: 1}) {
		t.Errorf("got suppressed=%v notifies=%v", e.Suppressed, e.Notifies)
	}
	if e.Priority != 3 {
		t.Errorf("priority = %d", e.Priority)
	}
}
