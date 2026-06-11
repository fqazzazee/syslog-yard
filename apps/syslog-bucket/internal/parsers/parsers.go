// Package parsers holds the vendor-normalization plugin layer. Parsers run after syslog-ng's wire-level parsing: they see
// an Entry already populated with host/app/severity/msg and enrich
// Entry.Structured with vendor-specific fields.
package parsers

import "github.com/syslog-yard/syslog-bucket/internal/store"

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

func (r *Registry) Apply(e *store.Entry) {
	for _, p := range r.parsers {
		if p.Match(e) {
			p.Normalize(e)
			return
		}
	}
}
