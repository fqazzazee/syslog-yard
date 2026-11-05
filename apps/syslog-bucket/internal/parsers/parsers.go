// Package parsers holds the vendor-normalization plugin layer. Parsers run after syslog-ng's wire-level parsing: they see
// an Entry already populated with host/app/severity/msg and enrich
// Entry.Structured with vendor-specific fields.
package parsers

import (
	"strings"

	"github.com/syslog-yard/syslog-bucket/internal/store"
)

type Parser interface {
	Name() string
	// Match reports whether this parser understands the entry.
	Match(e *store.Entry) bool
	// Normalize enriches the entry in place (typically Structured fields).
	Normalize(e *store.Entry)
}

// Registry applies the first matching parser. Vendor packs (Cisco, Claroty,
// ...) register ahead of the catch-all generic parser.
type Registry struct {
	parsers []Parser
}

func NewRegistry(parsers ...Parser) *Registry {
	return &Registry{parsers: parsers}
}

// Default is the production registry: the vendor parsers, then Generic.
func Default() *Registry {
	return NewRegistry(FortiGate{}, SonicWall{}, PANOS{}, Generic{})
}

func (r *Registry) Apply(e *store.Entry) {
	repairProgram(e)
	for _, p := range r.parsers {
		if p.Match(e) {
			p.Normalize(e)
			return
		}
	}
}

// repairProgram undoes syslog-ng's RFC 3164 parse of a line whose payload
// starts where a program name would. Devices that send "<PRI>payload" with
// no timestamp or host (FortiGate "date=…", SonicWall "id=firewall"), or a
// timestamp and host but no program (PAN-OS "1,2026/11/05 …"), lose their
// first payload token to PROGRAM. This happens in syslog-ng (the valve's and
// the bucket's alike), not in transport, and syslog-ng has no option to
// skip program parsing for such lines, so it is undone here: the token goes
// back in front of the message and the app is left for a vendor parser.
func repairProgram(e *store.Entry) {
	if !misparsedProgram(e.AppName) {
		return
	}
	if e.Msg == "" {
		e.Msg = e.AppName
	} else {
		e.Msg = e.AppName + " " + e.Msg
	}
	e.AppName = ""
}

// misparsedProgram reports whether a PROGRAM value is really payload: a
// key=value token, a quoted string, or a CSV record (digit-led, with
// commas). Program names carry none of these; topic lists such as
// MikroTik's "system,info" start with a letter and are left alone.
func misparsedProgram(app string) bool {
	if app == "" {
		return false
	}
	if strings.ContainsAny(app, `="`) {
		return true
	}
	return app[0] >= '0' && app[0] <= '9' && strings.Contains(app, ",")
}
