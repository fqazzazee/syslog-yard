// Package engine evaluates rules against entries at ingest time.
// It keeps an in-memory snapshot of enabled rules, refreshed when the API
// mutates rules and periodically as a safety net. The retroactive
// counterpart (apply a rule to history) lives in store.ApplyRuleHistorical,
// where it runs as set-based SQL.
package engine

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/syslog-yard/syslog-bucket/internal/store"
)

const refreshInterval = 30 * time.Second

type Engine struct {
	store *store.Store

	mu    sync.RWMutex
	rules []store.Rule
}

func New(st *store.Store) *Engine {
	return &Engine{store: st}
}

// Reload replaces the rule snapshot with the enabled rules in order.
func (g *Engine) Reload(ctx context.Context) error {
	all, err := g.store.ListRules(ctx)
	if err != nil {
		return err
	}
	enabled := all[:0]
	for _, r := range all {
		if r.Enabled {
			enabled = append(enabled, r)
		}
	}
	g.mu.Lock()
	g.rules = enabled
	g.mu.Unlock()
	return nil
}

// Run refreshes the snapshot periodically until ctx is cancelled, covering
// rule edits made outside this process (e.g. straight in the database).
func (g *Engine) Run(ctx context.Context) {
	ticker := time.NewTicker(refreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if err := g.Reload(ctx); err != nil && ctx.Err() == nil {
				slog.Error("engine: reload rules", "error", err)
			}
		case <-ctx.Done():
			return
		}
	}
}

// Apply runs every matching rule's actions against the entry in place,
// before it is inserted. Later rules win on priority; tags accumulate.
func (g *Engine) Apply(e *store.Entry) {
	g.mu.RLock()
	rules := g.rules
	g.mu.RUnlock()

	for _, r := range rules {
		if !r.Condition.Match(e) {
			continue
		}
		for _, a := range r.Actions {
			switch a.Type {
			case "tag":
				if !e.HasTag(a.TagID) {
					e.TagIDs = append(e.TagIDs, a.TagID)
					e.RuleTags = append(e.RuleTags, store.RuleTag{TagID: a.TagID, RuleID: r.ID})
				}
			case "set_priority":
				e.Priority = a.Priority
			case "suppress":
				e.Suppressed = true
			case "notify":
				// Queue the delivery; the dispatcher fires it after the
				// entry is stored. Ingest-only — historical apply never
				// notifies, so editing a rule can't trigger an alert storm.
				e.Notifies = append(e.Notifies, store.Notify{ChannelID: a.ChannelID, RuleID: r.ID})
			}
		}
	}
}
