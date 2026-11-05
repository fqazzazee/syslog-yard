package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/syslog-yard/syslog-bucket/internal/auth"
	"github.com/syslog-yard/syslog-bucket/internal/store"
)

// --- notification channels ---
//
// Channels are managed by analysts/admins (the auth middleware already blocks
// viewers from non-GET). SMTP passwords are write-only: redacted on read,
// preserved on update when left blank — but only while the server they are
// sent to stays the same, so an edit can't redirect a stored password to a
// host the editor controls.

func (s *server) listChannels(w http.ResponseWriter, r *http.Request) {
	channels, err := s.store.ListChannels(r.Context())
	if err != nil {
		s.internalError(w, "list channels", err)
		return
	}
	editor := canEditChannels(auth.UserFrom(r.Context()))
	for i := range channels {
		channels[i].Config = redactConfig(channels[i].Config, editor)
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
	created.Config = redactConfig(created.Config, true)
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
	merged, err := mergeSecrets(*existing, c)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c.Config = merged
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
	c.Config = redactConfig(c.Config, true)
	writeJSON(w, c)
}

func (s *server) deleteChannel(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	if err := s.store.DeleteChannel(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrInUse) {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
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
	// Delivery errors can quote the channel URL; viewers get it masked like
	// the channel list does.
	if !canEditChannels(auth.UserFrom(r.Context())) {
		for i := range log {
			log[i].Detail = scrubURLs(log[i].Detail)
		}
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

// canEditChannels reports whether u may see channel configs in full. Viewers
// can list channels (to read the delivery log) but never edit them, so they
// have no need for the webhook/Slack URLs — which are bearer secrets.
func canEditChannels(u *store.User) bool {
	return u != nil && u.Role != store.RoleViewer
}

// redactConfig blanks the SMTP password on read and flags whether one is set,
// so the UI can show "leave blank to keep" without ever shipping the secret.
// For non-editors (viewers) it also cuts webhook/Slack URLs down to scheme and
// host, flagging has_url, since anyone holding the full URL can post to it.
func redactConfig(raw json.RawMessage, editor bool) json.RawMessage {
	m := map[string]any{}
	if len(raw) == 0 || json.Unmarshal(raw, &m) != nil {
		if editor {
			return raw
		}
		return json.RawMessage(`{}`)
	}
	if pw, ok := m["password"]; ok {
		m["has_password"] = pw != nil && pw != ""
		m["password"] = ""
	}
	if u, ok := m["url"]; ok && !editor {
		s, _ := u.(string)
		m["has_url"] = s != ""
		m["url"] = maskURL(s)
	}
	out, err := json.Marshal(m)
	if err != nil {
		if editor {
			return raw
		}
		return json.RawMessage(`{}`)
	}
	return out
}

// maskURL keeps only the scheme and host of a URL — enough to tell a Slack
// hook from a generic webhook, nothing that would let the reader use it.
func maskURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host + "/…"
}

// urlInText matches URLs embedded in free text such as delivery errors (Go's
// HTTP client quotes the full request URL in its errors): scheme, optional
// userinfo, host, then the rest up to a delimiter.
var urlInText = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.\-]*://)(?:[^@/\s"'<>]*@)?([^/\s"'<>?#]+)[^\s"'<>]*`)

// scrubURLs masks every URL in s to scheme://host/… .
func scrubURLs(s string) string {
	return urlInText.ReplaceAllString(s, "${1}${2}/…")
}

// errSecretReentry answers an edit that moves an SMTP channel to a different
// server or account without supplying the password again.
var errSecretReentry = errors.New("the SMTP host, port, username, or TLS mode changed — re-enter the password")

// smtpTarget is the part of an SMTP config a stored password is bound to:
// where it is sent and as whom. Defaults are normalised the way the sender
// applies them, so "port omitted" and "587" compare equal.
type smtpTarget struct {
	Host     string      `json:"host"`
	Port     json.Number `json:"port"`
	Username string      `json:"username"`
	TLS      string      `json:"tls"`
}

func parseSMTPTarget(raw json.RawMessage) (smtpTarget, bool) {
	var t smtpTarget
	if json.Unmarshal(raw, &t) != nil {
		return t, false
	}
	t.Host = strings.ToLower(strings.TrimSpace(t.Host))
	t.Username = strings.TrimSpace(t.Username)
	if t.Port == "" || t.Port == "0" {
		t.Port = "587"
	}
	if t.TLS == "" {
		t.TLS = "starttls"
	}
	return t, true
}

// mergeSecrets carries a stored password forward when the incoming config
// leaves it blank — provided the channel still talks to the same SMTP server
// as the same user. Otherwise the stored password is discarded, and when the
// new config needs one (a username is set) the edit is refused with
// errSecretReentry rather than silently sending without the password.
func mergeSecrets(existing, incoming store.Channel) (json.RawMessage, error) {
	in := map[string]any{}
	if len(incoming.Config) == 0 || json.Unmarshal(incoming.Config, &in) != nil {
		return incoming.Config, nil
	}
	delete(in, "has_password") // never persist the read-only flag
	if pw, ok := in["password"].(string); ok && pw == "" {
		old := map[string]any{}
		_ = json.Unmarshal(existing.Config, &old)
		if oldPw, ok := old["password"].(string); ok && oldPw != "" {
			oldT, okOld := parseSMTPTarget(existing.Config)
			newT, okNew := parseSMTPTarget(incoming.Config)
			switch {
			case existing.Kind == incoming.Kind && okOld && okNew && oldT == newT:
				in["password"] = oldPw
			case incoming.Kind == "smtp" && newT.Username != "":
				return nil, errSecretReentry
			}
		}
	}
	out, err := json.Marshal(in)
	if err != nil {
		return incoming.Config, nil
	}
	return out, nil
}
