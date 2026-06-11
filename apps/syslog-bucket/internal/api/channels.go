package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/syslog-yard/syslog-bucket/internal/store"
)

// --- notification channels ---
//
// Channels are managed by analysts/admins (the auth middleware already blocks
// viewers from non-GET). SMTP passwords are write-only: redacted on read,
// preserved on update when left blank.

func (s *server) listChannels(w http.ResponseWriter, r *http.Request) {
	channels, err := s.store.ListChannels(r.Context())
	if err != nil {
		s.internalError(w, "list channels", err)
		return
	}
	for i := range channels {
		channels[i].Config = redactConfig(channels[i].Config)
	}
	writeJSON(w, map[string]any{"channels": channels})
}

func (s *server) createChannel(w http.ResponseWriter, r *http.Request) {
	var c store.Channel
	if !decodeJSON(w, r, &c) || !validChannel(w, c) {
		return
	}
	created, err := s.store.CreateChannel(r.Context(), c)
	if err != nil {
		s.writeError(w, "create channel", err)
		return
	}
	s.reloadNotifier(r)
	created.Config = redactConfig(created.Config)
	writeJSON(w, created)
}

func (s *server) updateChannel(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var c store.Channel
	if !decodeJSON(w, r, &c) || !validChannel(w, c) {
		return
	}
	c.ID = id
	// Preserve a stored secret the UI didn't resend (blank password = keep).
	existing, err := s.store.GetChannel(r.Context(), id)
	if err != nil {
		s.internalError(w, "get channel", err)
		return
	}
	if existing == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	c.Config = mergeSecrets(existing.Config, c.Config)
	found, err := s.store.UpdateChannel(r.Context(), c)
	if err != nil {
		s.writeError(w, "update channel", err)
		return
	}
	if !found {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	s.reloadNotifier(r)
	c.Config = redactConfig(c.Config)
	writeJSON(w, c)
}

func (s *server) deleteChannel(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	if err := s.store.DeleteChannel(r.Context(), id); err != nil {
		s.internalError(w, "delete channel", err)
		return
	}
	s.reloadNotifier(r)
	w.WriteHeader(http.StatusNoContent)
}

// testChannel sends a synthetic notification so the user can confirm a channel
// is wired up. Returns 200 on success, 502 with the delivery error otherwise.
func (s *server) testChannel(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	ch, err := s.store.GetChannel(r.Context(), id)
	if err != nil {
		s.internalError(w, "get channel", err)
		return
	}
	if ch == nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if s.notifier == nil {
		http.Error(w, "notifications disabled", http.StatusServiceUnavailable)
		return
	}
	if err := s.notifier.TestSend(r.Context(), *ch); err != nil {
		http.Error(w, "delivery failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *server) notificationLog(w http.ResponseWriter, r *http.Request) {
	var channelID *int64
	if v := r.URL.Query().Get("channel_id"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			http.Error(w, "channel_id must be numeric", http.StatusBadRequest)
			return
		}
		channelID = &n
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	log, err := s.store.RecentDeliveries(r.Context(), channelID, limit)
	if err != nil {
		s.internalError(w, "notification log", err)
		return
	}
	writeJSON(w, map[string]any{"deliveries": log})
}

func (s *server) reloadNotifier(r *http.Request) {
	if s.notifier == nil {
		return
	}
	if err := s.notifier.Reload(r.Context()); err != nil {
		slog.Error("api: reload notifier", "error", err)
	}
}

func validChannel(w http.ResponseWriter, c store.Channel) bool {
	if strings.TrimSpace(c.Name) == "" {
		http.Error(w, "channel name required", http.StatusBadRequest)
		return false
	}
	switch c.Kind {
	case "webhook", "slack", "smtp":
	default:
		http.Error(w, "kind must be webhook, slack, or smtp", http.StatusBadRequest)
		return false
	}
	if c.RatePerMin < 0 {
		http.Error(w, "rate_per_min must be >= 0", http.StatusBadRequest)
		return false
	}
	return true
}

// redactConfig blanks the SMTP password on read and flags whether one is set,
// so the UI can show "leave blank to keep" without ever shipping the secret.
func redactConfig(raw json.RawMessage) json.RawMessage {
	m := map[string]any{}
	if len(raw) == 0 || json.Unmarshal(raw, &m) != nil {
		return raw
	}
	if pw, ok := m["password"]; ok {
		m["has_password"] = pw != nil && pw != ""
		m["password"] = ""
	}
	out, err := json.Marshal(m)
	if err != nil {
		return raw
	}
	return out
}

// mergeSecrets carries a stored password forward when the incoming config
// leaves it blank.
func mergeSecrets(existing, incoming json.RawMessage) json.RawMessage {
	in := map[string]any{}
	if len(incoming) == 0 || json.Unmarshal(incoming, &in) != nil {
		return incoming
	}
	if pw, ok := in["password"].(string); ok && pw == "" {
		old := map[string]any{}
		if json.Unmarshal(existing, &old) == nil {
			if oldPw, ok := old["password"].(string); ok && oldPw != "" {
				in["password"] = oldPw
			}
		}
	}
	delete(in, "has_password") // never persist the read-only flag
	out, err := json.Marshal(in)
	if err != nil {
		return incoming
	}
	return out
}
