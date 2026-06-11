// Package otmap classifies ingested OT/ICS security events into Claroty-style
// alert categories. It is the OT counterpart of internal/mitre: a small,
// curated catalog (two categories — Security and Integrity — each holding a
// set of alert types) plus a detection table that reuses the shared condition
// AST (internal/rules) to recognise an alert the same way a bucket or rule
// would.
//
// The mapping runs at ingest, after the parsers, and stamps each entry with
// the alert-type codes it matched (stored in entries.ot). The bucket then
// groups by category/alert-type in the OT view, the way it does for ATT&CK
// tactics/techniques. Claroty CTD and xDome emit CEF over syslog where the
// CEF Name field is the alert type; the syslog generator (syslog-hose) wraps
// that Name in pipes, so each detection keys off a "|<Name>|" token in the
// raw message — robust without a dedicated CEF parser.
package otmap

import (
	"sort"

	"github.com/syslog-yard/syslog-bucket/internal/rules"
)

// Category is one Claroty alert class (a column in the OT view). Order is the
// order the UI lays the columns out in.
type Category struct {
	ID    string `json:"id"`    // e.g. "security"
	Short string `json:"short"` // join key used by alert types
	Name  string `json:"name"`  // e.g. "Security"
}

// AlertType is one Claroty alert type, tagged with the category it belongs to.
type AlertType struct {
	ID         string   `json:"id"`         // short code, e.g. "CL-KT"
	Name       string   `json:"name"`       // e.g. "Known Threat" (the CEF Name)
	Categories []string `json:"categories"` // category Short names
}

// detection binds an alert type to the condition that recognises it.
type detection struct {
	alert string
	cond  rules.Cond
}

// Catalog is the JSON shape served to the UI.
type Catalog struct {
	Categories []Category  `json:"categories"`
	AlertTypes []AlertType `json:"alert_types"`
}

func leaf(field, op string, value any) rules.Cond {
	return rules.Cond{Field: field, Op: op, Value: value}
}

// Claroty's two top-level alert classes, in view order.
var categories = []Category{
	{"security", "security", "Security"},
	{"integrity", "integrity", "Integrity"},
}

// alert types this build recognises, grouped by category.
var alertTypes = []AlertType{
	// Security — threat-oriented.
	{"CL-KT", "Known Threat", []string{"security"}},
	{"CL-SUS", "Suspicious Activity", []string{"security"}},
	{"CL-SCAN", "Network Scan", []string{"security"}},
	{"CL-UA", "Unauthorized Access", []string{"security"}},
	{"CL-POL", "Policy Violation", []string{"security"}},
	{"CL-MAL", "Malware / Exploit", []string{"security"}},
	// Integrity — change / operational integrity.
	{"CL-NEWA", "New Asset", []string{"integrity"}},
	{"CL-CHG", "Asset Change", []string{"integrity"}},
	{"CL-BASE", "Baseline Deviation", []string{"integrity"}},
	{"CL-CFG", "Configuration Download", []string{"integrity"}},
	{"CL-MODE", "PLC Mode Change", []string{"integrity"}},
	{"CL-CONF", "IP/MAC Conflict", []string{"integrity"}},
}

// detections recognise a Claroty alert from the CEF Name token the generator
// emits (the Name field surrounded by pipes), so they never collide with the
// free-text msg= extension. One detection per alert type.
var detections = []detection{
	{"CL-KT", leaf("msg", "contains", "|Known Threat|")},
	{"CL-SUS", leaf("msg", "contains", "|Suspicious Activity|")},
	{"CL-SCAN", leaf("msg", "contains", "|Network Scan|")},
	{"CL-UA", leaf("msg", "contains", "|Unauthorized Access|")},
	{"CL-POL", leaf("msg", "contains", "|Policy Violation|")},
	{"CL-MAL", leaf("msg", "contains", "|Malware / Exploit|")},
	{"CL-NEWA", leaf("msg", "contains", "|New Asset|")},
	{"CL-CHG", leaf("msg", "contains", "|Asset Change|")},
	{"CL-BASE", leaf("msg", "contains", "|Baseline Deviation|")},
	{"CL-CFG", leaf("msg", "contains", "|Configuration Download|")},
	{"CL-MODE", leaf("msg", "contains", "|PLC Mode Change|")},
	{"CL-CONF", leaf("msg", "contains", "|IP/MAC Conflict|")},
}

// Map returns the sorted, de-duplicated alert-type codes that match rec. Safe
// for concurrent use (the detection table is read-only).
func Map(rec rules.Record) []string {
	var hits []string
	seen := map[string]bool{}
	for _, d := range detections {
		if seen[d.alert] {
			continue
		}
		if d.cond.Match(rec) {
			seen[d.alert] = true
			hits = append(hits, d.alert)
		}
	}
	sort.Strings(hits)
	return hits
}

// catalog is assembled once; the slices above never change at runtime.
var catalog = Catalog{Categories: categories, AlertTypes: alertTypes}

// Get returns the alert catalog served at /api/ot.
func Get() Catalog { return catalog }
