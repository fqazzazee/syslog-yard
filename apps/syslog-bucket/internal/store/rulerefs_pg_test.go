package store_test

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"testing"

	"github.com/syslog-yard/syslog-bucket/internal/rules"
	"github.com/syslog-yard/syslog-bucket/internal/store"
	"github.com/syslog-yard/syslog-bucket/internal/store/storetest"
	"github.com/syslog-yard/syslog-bucket/migrations"
)

// Enabled rules can only point at tags and channels that exist, and only
// disabled rules can be left pointing at deleted ones — enforced by the
// rule_refs foreign keys, not by a check that a concurrent write could race.
func TestRuleRefsEnforceTargets(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	tag, _ := st.CreateTag(ctx, store.Tag{Name: "t"})
	ch, err := st.CreateChannel(ctx, store.Channel{Name: "c", Kind: "webhook", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}

	// An enabled rule can't be created against a missing target.
	_, err = st.CreateRule(ctx, store.Rule{Name: "ghost", Enabled: true, Actions: []rules.Action{{Type: "tag", TagID: 999999}}})
	var missing *store.MissingRefError
	if !errors.Is(err, store.ErrMissingRef) || !errors.As(err, &missing) || !slices.Equal(missing.Tags, []int64{999999}) {
		t.Fatalf("create with missing tag: err = %v", err)
	}
	_, err = st.CreateRule(ctx, store.Rule{Name: "ghost", Enabled: true, Actions: []rules.Action{{Type: "notify", ChannelID: 999999}}})
	if !errors.As(err, &missing) || !slices.Equal(missing.Channels, []int64{999999}) {
		t.Fatalf("create with missing channel: err = %v", err)
	}

	// The same target twice in one rule is one reference, not a conflict.
	rule, err := st.CreateRule(ctx, store.Rule{Name: "twice", Enabled: true, Actions: []rules.Action{
		{Type: "tag", TagID: tag.ID}, {Type: "tag", TagID: tag.ID}, {Type: "notify", ChannelID: ch.ID},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteTag(ctx, tag.ID); !errors.Is(err, store.ErrInUse) {
		t.Fatalf("DeleteTag in use: err = %v", err)
	}

	// Disable, delete the tag, then try to enable again: refused, and the
	// rule stays as it was.
	rule.Enabled = false
	if _, err := st.UpdateRule(ctx, rule); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteTag(ctx, tag.ID); err != nil {
		t.Fatalf("DeleteTag after disabling: %v", err)
	}
	rule.Enabled = true
	if _, err := st.UpdateRule(ctx, rule); !errors.As(err, &missing) || !slices.Equal(missing.Tags, []int64{tag.ID}) {
		t.Fatalf("re-enable with deleted tag: err = %v", err)
	}
	got, err := st.GetRule(ctx, rule.ID)
	if err != nil || got.Enabled {
		t.Fatalf("rule after refused update: %+v %v", got, err)
	}

	// Deleting a rule releases its references.
	rule.Actions = []rules.Action{{Type: "notify", ChannelID: ch.ID}}
	if _, err := st.UpdateRule(ctx, rule); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteChannel(ctx, ch.ID); !errors.Is(err, store.ErrInUse) {
		t.Fatalf("DeleteChannel in use: err = %v", err)
	}
	if err := st.DeleteRule(ctx, rule.ID); err != nil {
		t.Fatal(err)
	}
	if err := st.DeleteChannel(ctx, ch.ID); err != nil {
		t.Fatalf("DeleteChannel after rule deleted: %v", err)
	}
}

// Upgrading a database with rules backfills rule_refs from the enabled rules,
// skipping a reference to a tag that is already gone instead of failing.
func TestRuleRefsMigrationBackfill(t *testing.T) {
	st := storetest.New(t)
	ctx := context.Background()
	if _, err := st.Pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public;
		CREATE TABLE schema_migrations (filename TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	for _, name := range migrationFiles(t) {
		if name >= "0010" {
			break
		}
		sql, _ := migrations.FS.ReadFile(name)
		if _, err := st.Pool.Exec(ctx, string(sql)); err != nil {
			t.Fatalf("replay %s: %v", name, err)
		}
		st.Pool.Exec(ctx, `INSERT INTO schema_migrations (filename) VALUES ($1)`, name)
	}
	var tagID, chID int64
	st.Pool.QueryRow(ctx, `INSERT INTO tags (name) VALUES ('t') RETURNING id`).Scan(&tagID)
	st.Pool.QueryRow(ctx, `INSERT INTO notification_channels (name, kind, enabled, config) VALUES ('c', 'webhook', true, '{}') RETURNING id`).Scan(&chID)
	for _, r := range []struct {
		name    string
		enabled bool
		actions string
	}{
		{"uses both", true, `[{"type":"tag","tag_id":` + strconv.FormatInt(tagID, 10) + `},{"type":"notify","channel_id":` + strconv.FormatInt(chID, 10) + `}]`},
		{"dangling", true, `[{"type":"tag","tag_id":424242}]`},
		{"disabled", false, `[{"type":"tag","tag_id":` + strconv.FormatInt(tagID, 10) + `}]`},
	} {
		if _, err := st.Pool.Exec(ctx, `INSERT INTO rules (name, enabled, position, condition, actions) VALUES ($1, $2, 0, '{}', $3)`,
			r.name, r.enabled, r.actions); err != nil {
			t.Fatal(err)
		}
	}
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("upgrade: %v", err)
	}
	var n int
	st.Pool.QueryRow(ctx, `SELECT count(*) FROM rule_refs`).Scan(&n)
	if n != 2 {
		t.Errorf("backfilled %d rule_refs rows, want 2 (tag + channel of the enabled rule)", n)
	}
	var inUse *store.InUseError
	if err := st.DeleteTag(ctx, tagID); !errors.As(err, &inUse) || !slices.Equal(inUse.Rules, []string{"uses both"}) {
		t.Errorf("DeleteTag after upgrade: err = %v", err)
	}
}
