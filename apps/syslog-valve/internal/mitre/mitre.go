// Package mitre carries the ATT&CK techniques the valve can filter on.
// Unlike the bucket — which maps techniques from fully parsed structured
// fields — the valve matches on the raw syslog line as it crosses syslog-ng,
// so each technique is expressed as a syslog-ng filter pattern (a PCRE over
// the message, and/or a program name).
//
// The vocabulary (IDs, names, tactics) comes from the suite-wide catalog in
// github.com/syslog-yard/shared/attack; this package only adds the wire
// patterns. Patterns target the demo vocabulary (FortiGate key=value,
// sshd/sudo text).
package mitre

import "github.com/syslog-yard/shared/attack"

// Tactic is one ATT&CK tactic; Short is the join key used by techniques.
type Tactic = attack.Tactic

// Technique is one ATT&CK technique plus the syslog-ng match that recognises
// it on the wire. At least one of Message (a PCRE applied to the message) or
// Program (an exact program/app name) is set.
type Technique struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	Tactics []string `json:"tactics"`
	Message string   `json:"-"` // PCRE for syslog-ng message()
	Program string   `json:"-"` // syslog-ng program()
}

// Catalog is the JSON shape served to the UI's technique picker.
type Catalog struct {
	Tactics    []Tactic    `json:"tactics"`
	Techniques []Technique `json:"techniques"`
}

// patterns is the valve's contribution per technique: how to recognise it in
// the raw stream. Keyed by technique ID; the IDs must exist in the shared
// catalog (enforced by TestPatternsMatchCatalog).
var patterns = map[string]struct {
	Message string
	Program string
}{
	"T1190": {Message: `Code\.Execution`},
	"T1110": {Message: `Failed password|status="failed"`},
	"T1078": {Message: `Accepted (password|publickey)|status="success"|AAA user.*Successful`},
	"T1204": {Message: `subtype="virus"`},
	"T1566": {Message: `catdesc="Phishing"`},
	"T1071": {Message: `Cobalt`},
	"T1021": {Message: `action="deny".*service="(SSH|RDP|SMB|TELNET|MSSQL)"`},
	"T1548": {Program: "sudo"},
	"T1499": {Message: "SYN flooding"},
}

// techniques joins the shared catalog with the local patterns, preserving
// catalog order. A catalog entry without a pattern is skipped: the valve can
// only offer techniques it can actually match on the wire.
var techniques = func() []Technique {
	out := make([]Technique, 0, len(patterns))
	for _, t := range attack.Techniques {
		p, ok := patterns[t.ID]
		if !ok {
			continue
		}
		out = append(out, Technique{
			ID: t.ID, Name: t.Name, Tactics: t.Tactics,
			Message: p.Message, Program: p.Program,
		})
	}
	return out
}()

var byID = func() map[string]Technique {
	m := make(map[string]Technique, len(techniques))
	for _, t := range techniques {
		m[t.ID] = t
	}
	return m
}()

// Lookup returns the technique for an ID and whether it is known.
func Lookup(id string) (Technique, bool) {
	t, ok := byID[id]
	return t, ok
}

// Get returns the catalog served at /api/mitre.
func Get() Catalog { return Catalog{Tactics: attack.Tactics, Techniques: techniques} }
