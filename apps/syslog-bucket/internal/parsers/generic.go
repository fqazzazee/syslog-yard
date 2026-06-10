package parsers

import (
	"encoding/json"
	"strings"

	"github.com/syslog-yard/syslog-bucket/internal/store"
)

// Generic is the catch-all parser: it extracts key=value pairs (the most
// common structured convention in syslog payloads) into Entry.Structured.
type Generic struct{}

func (Generic) Name() string                { return "generic" }
func (Generic) Match(_ *store.Entry) bool   { return true }

const maxStructuredKeys = 50

func (Generic) Normalize(e *store.Entry) {
	fields := extractKV(e.Msg)
	if len(fields) == 0 {
		return
	}
	// Merge on top of anything the ingest layer already recorded.
	existing := map[string]string{}
	if len(e.Structured) > 0 {
		json.Unmarshal(e.Structured, &existing)
	}
	for k, v := range fields {
		existing[k] = v
	}
	if b, err := json.Marshal(existing); err == nil {
		e.Structured = b
	}
}

// extractKV pulls key=value and key="quoted value" tokens out of a message.
func extractKV(msg string) map[string]string {
	fields := map[string]string{}
	i := 0
	for i < len(msg) && len(fields) < maxStructuredKeys {
		eq := strings.IndexByte(msg[i:], '=')
		if eq < 0 {
			break
		}
		eq += i

		// Walk back from '=' to find the key start.
		start := eq
		for start > 0 && isKeyChar(msg[start-1]) {
			start--
		}
		key := msg[start:eq]
		if key == "" || eq+1 >= len(msg) {
			i = eq + 1
			continue
		}

		// Value: quoted or up to next whitespace/comma.
		var value string
		rest := msg[eq+1:]
		if rest[0] == '"' {
			if end := strings.IndexByte(rest[1:], '"'); end >= 0 {
				value = rest[1 : 1+end]
				i = eq + 2 + end + 1
			} else {
				i = eq + 1
				continue
			}
		} else {
			end := strings.IndexFunc(rest, func(r rune) bool { return r == ' ' || r == '\t' || r == ',' })
			if end < 0 {
				end = len(rest)
			}
			value = rest[:end]
			i = eq + 1 + end
		}
		if value != "" {
			fields[key] = value
		}
	}
	return fields
}

func isKeyChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.'
}
