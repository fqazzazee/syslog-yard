// Package audit records administrative and triage actions (sign-ins, account
// and settings changes, rule/bucket/tag/channel/framework edits, entry
// triage) in the audit_log table.
//
// Recording never blocks or fails the request that triggers it: Record only
// queues the event, and a single writer goroutine inserts queued events in
// batches. If the queue is full or a write fails, the event is written to the
// process log instead (at warning level, so it is not lost silently) and the
// request carries on.
//
// Summaries are built by the callers from an allow-list of fields — never
// from a request body — so passwords, client secrets and webhook URLs cannot
// reach the table.
package audit

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/syslog-yard/syslog-bucket/internal/store"
)

// Action names, "<target type>.<verb>". The UI lists the same set.
const (
	SignIn         = "auth.login"
	SignOut        = "auth.logout"
	PasswordChange = "auth.password_change"

	UserCreate        = "user.create"
	UserUpdate        = "user.update"
	UserPasswordReset = "user.password_reset"
	UserDelete        = "user.delete"

	SettingsOIDC    = "settings.oidc"
	SettingsSession = "settings.session"

	RuleCreate = "rule.create"
	RuleUpdate = "rule.update"
	RuleDelete = "rule.delete"
	RuleApply  = "rule.apply"

	BucketCreate = "bucket.create"
	BucketUpdate = "bucket.update"
	BucketDelete = "bucket.delete"
	BucketShare  = "bucket.share"

	TagCreate = "tag.create"
	TagUpdate = "tag.update"
	TagDelete = "tag.delete"

	ChannelCreate = "channel.create"
	ChannelUpdate = "channel.update"
	ChannelDelete = "channel.delete"

	FrameworkCreate = "framework.create"
	FrameworkUpdate = "framework.update"
	FrameworkDelete = "framework.delete"

	EntryUpdate   = "entry.update"
	EntryTag      = "entry.tag"
	EntryUntag    = "entry.untag"
	EntryClassify = "entry.classify"

	NetConfig = "net.config"
)

// Event is one action to record. Summary is marshalled to JSON; keep it to a
// handful of identifying fields.
type Event struct {
	ActorID    *int64
	ActorName  string
	ActorIP    string
	Action     string
	TargetType string
	TargetID   string
	Summary    map[string]any
	Success    bool
}

// As returns ev with its actor set from u (a nil u leaves it blank).
func (ev Event) As(u *store.User) Event {
	if u != nil {
		id := u.ID
		ev.ActorID, ev.ActorName = &id, u.Username
	}
	return ev
}

// Writer is the storage the recorder writes to (the store, or a test fake).
type Writer interface {
	InsertAudit(ctx context.Context, events []store.AuditEvent) error
	PruneAudit(ctx context.Context, olderThan time.Duration) (int64, error)
}

const (
	queueSize     = 4096
	maxBatch      = 256
	writeTimeout  = 10 * time.Second
	pruneInterval = time.Hour
	// maxNameLen caps the actor name, which for failed sign-ins is whatever
	// the client typed.
	maxNameLen = 128
)

// Recorder queues events and writes them in the background. A nil *Recorder
// is valid and records nothing.
type Recorder struct {
	w         Writer
	retention time.Duration // 0 = keep forever

	mu     sync.RWMutex // guards closed and sends on queue
	closed bool
	queue  chan store.AuditEvent
	done   chan struct{}
}

// New starts a recorder writing to w. Rows older than retention are pruned
// while Run is active; retention <= 0 keeps them forever.
func New(w Writer, retention time.Duration) *Recorder {
	r := &Recorder{
		w:         w,
		retention: retention,
		queue:     make(chan store.AuditEvent, queueSize),
		done:      make(chan struct{}),
	}
	go r.write()
	return r
}

// Record queues ev. It never blocks: a full queue (or a recorder already shut
// down) sends the event to the process log instead.
func (r *Recorder) Record(ev Event) {
	if r == nil {
		return
	}
	row := store.AuditEvent{
		Time:       time.Now(),
		ActorID:    ev.ActorID,
		ActorName:  truncate(ev.ActorName, maxNameLen),
		ActorIP:    ev.ActorIP,
		Action:     ev.Action,
		TargetType: ev.TargetType,
		TargetID:   ev.TargetID,
		Success:    ev.Success,
	}
	if len(ev.Summary) > 0 {
		b, err := json.Marshal(ev.Summary)
		if err != nil {
			slog.Error("audit: marshal summary", "action", ev.Action, "error", err)
			b = []byte(`{}`)
		}
		row.Summary = b
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.closed {
		logLost("recorder stopped", row)
		return
	}
	select {
	case r.queue <- row:
	default:
		logLost("queue full", row)
	}
}

// write drains the queue in batches until Shutdown closes it.
func (r *Recorder) write() {
	defer close(r.done)
	for first := range r.queue {
		batch := []store.AuditEvent{first}
	more:
		for len(batch) < maxBatch {
			select {
			case ev, ok := <-r.queue:
				if !ok {
					break more
				}
				batch = append(batch, ev)
			default:
				break more
			}
		}
		ctx, cancel := context.WithTimeout(context.Background(), writeTimeout)
		err := r.w.InsertAudit(ctx, batch)
		cancel()
		if err != nil {
			slog.Error("audit: write failed", "events", len(batch), "error", err)
			for _, ev := range batch {
				logLost("write failed", ev)
			}
		}
	}
}

// Run prunes expired rows at start and then hourly, until ctx ends.
func (r *Recorder) Run(ctx context.Context) {
	if r == nil || r.retention <= 0 {
		return
	}
	t := time.NewTicker(pruneInterval)
	defer t.Stop()
	for {
		r.prune(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (r *Recorder) prune(ctx context.Context) {
	n, err := r.w.PruneAudit(ctx, r.retention)
	switch {
	case err != nil && ctx.Err() == nil:
		slog.Error("audit: prune", "error", err)
	case n > 0:
		slog.Info("audit: pruned expired rows", "rows", n, "retention", r.retention)
	}
}

// Shutdown stops accepting events and waits up to timeout for queued ones to
// be written.
func (r *Recorder) Shutdown(timeout time.Duration) {
	if r == nil {
		return
	}
	r.mu.Lock()
	if !r.closed {
		r.closed = true
		close(r.queue)
	}
	r.mu.Unlock()
	select {
	case <-r.done:
	case <-time.After(timeout):
		slog.Warn("audit: shutdown timed out with events still queued")
	}
}

// logLost writes an event that didn't reach the table to the process log, so
// the trail survives there.
func logLost(why string, ev store.AuditEvent) {
	slog.Warn("audit: event not stored ("+why+")",
		"time", ev.Time, "action", ev.Action, "actor", ev.ActorName, "actor_id", ev.ActorID,
		"ip", ev.ActorIP, "target_type", ev.TargetType, "target_id", ev.TargetID,
		"success", ev.Success, "summary", string(ev.Summary))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// Cut on a rune boundary.
	for n > 0 && n < len(s) && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}
