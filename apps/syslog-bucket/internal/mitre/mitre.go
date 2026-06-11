// Package mitre maps ingested entries to MITRE ATT&CK techniques (suite S8).
// It carries a small, curated slice of the ATT&CK Enterprise matrix — the
// tactics and techniques that show up in the syslog the suite actually sees
// (firewall, IPS/AV, auth) — plus a detection table that reuses the shared
// condition AST (internal/rules) so a technique is recognised exactly the way
// a bucket or rule would match it.
//
// The mapping runs at ingest, after the parsers have populated structured
// fields, and stamps each entry with the technique IDs it matched. The bucket
// then sorts and groups by tactic/technique; the valve carries a parallel,
// syslog-ng-flavoured copy of the same catalog for its technique filter (keep
// the two technique lists in sync — see apps/syslog-valve/internal/mitre).
package mitre

import (
	"sort"

	"github.com/syslog-yard/syslog-bucket/internal/rules"
)

// Tactic is one ATT&CK tactic (a kill-chain column). Order follows the
// Enterprise matrix left-to-right so the UI can lay tactics out in sequence.
type Tactic struct {
	ID    string `json:"id"`    // e.g. "TA0006"
	Short string `json:"short"` // e.g. "credential-access" (used as the join key)
	Name  string `json:"name"`  // e.g. "Credential Access"
}

// Technique is one ATT&CK technique, tagged with the tactics it serves.
type Technique struct {
	ID      string   `json:"id"`      // e.g. "T1110"
	Name    string   `json:"name"`    // e.g. "Brute Force"
	Tactics []string `json:"tactics"` // tactic Short names
	URL     string   `json:"url"`     // attack.mitre.org reference
}

// detection binds a technique to the condition that recognises it.
type detection struct {
	technique string
	cond      rules.Cond
}

// Catalog is the JSON shape served to the UI: tactics in matrix order and the
// techniques this build knows about.
type Catalog struct {
	Tactics    []Tactic    `json:"tactics"`
	Techniques []Technique `json:"techniques"`
}

func leaf(field, op string, value any) rules.Cond {
	return rules.Cond{Field: field, Op: op, Value: value}
}

// tactics in ATT&CK Enterprise matrix order (only the ones our techniques use).
var tactics = []Tactic{
	{"TA0001", "initial-access", "Initial Access"},
	{"TA0002", "execution", "Execution"},
	{"TA0003", "persistence", "Persistence"},
	{"TA0004", "privilege-escalation", "Privilege Escalation"},
	{"TA0005", "defense-evasion", "Defense Evasion"},
	{"TA0006", "credential-access", "Credential Access"},
	{"TA0008", "lateral-movement", "Lateral Movement"},
	{"TA0011", "command-and-control", "Command and Control"},
	{"TA0040", "impact", "Impact"},
}

// techniques this build recognises. Each has at least one detection below.
var techniques = []Technique{
	{"T1190", "Exploit Public-Facing Application", []string{"initial-access"}, "https://attack.mitre.org/techniques/T1190/"},
	{"T1110", "Brute Force", []string{"credential-access"}, "https://attack.mitre.org/techniques/T1110/"},
	{"T1078", "Valid Accounts", []string{"initial-access", "persistence", "privilege-escalation", "defense-evasion"}, "https://attack.mitre.org/techniques/T1078/"},
	{"T1204", "User Execution", []string{"execution"}, "https://attack.mitre.org/techniques/T1204/"},
	{"T1566", "Phishing", []string{"initial-access"}, "https://attack.mitre.org/techniques/T1566/"},
	{"T1071", "Application Layer Protocol", []string{"command-and-control"}, "https://attack.mitre.org/techniques/T1071/"},
	{"T1021", "Remote Services", []string{"lateral-movement"}, "https://attack.mitre.org/techniques/T1021/"},
	{"T1548", "Abuse Elevation Control Mechanism", []string{"privilege-escalation", "defense-evasion"}, "https://attack.mitre.org/techniques/T1548/"},
	{"T1499", "Endpoint Denial of Service", []string{"impact"}, "https://attack.mitre.org/techniques/T1499/"},
}

// detections recognise techniques from the demo vocabulary (FortiGate
// key=value, sshd/sudo text, Cisco ASA text). Conditions match parsed
// structured fields where present, message text otherwise.
var detections = []detection{
	// IPS signatures whose names carry "...Code.Execution" (Log4j, Struts,
	// SMB RCE) — exploitation of an exposed service.
	{"T1190", leaf("structured.attack", "contains", "Code.Execution")},

	// FortiGate AV (subtype=virus) blocking an infected download the user
	// fetched, and ASA/host malware text.
	{"T1204", leaf("structured.subtype", "eq", "virus")},

	// FortiGate webfilter category Phishing.
	{"T1566", leaf("structured.catdesc", "eq", "Phishing")},

	// A beaconing C2 signature (Cobalt Strike) over an application protocol.
	{"T1071", leaf("structured.attack", "contains", "Cobalt")},

	// Failed authentication: sshd "Failed password" or a device login that
	// reported status=failed.
	{"T1110", rules.Cond{Any: []rules.Cond{
		leaf("msg", "contains", "Failed password"),
		{All: []rules.Cond{leaf("structured.action", "eq", "login"), leaf("structured.status", "eq", "failed")}},
	}}},

	// Successful authentication with valid credentials: sshd "Accepted ...",
	// a device login status=success, or Cisco ASA AAA success.
	{"T1078", rules.Cond{Any: []rules.Cond{
		leaf("msg", "contains", "Accepted password"),
		leaf("msg", "contains", "Accepted publickey"),
		{All: []rules.Cond{leaf("structured.action", "eq", "login"), leaf("structured.status", "eq", "success")}},
		{All: []rules.Cond{leaf("msg", "contains", "AAA user"), leaf("msg", "contains", "Successful")}},
	}}},

	// Inbound connection attempts to remote-access services (denied at the
	// firewall) — lateral-movement reconnaissance.
	{"T1021", rules.Cond{All: []rules.Cond{
		leaf("structured.action", "eq", "deny"),
		{Any: []rules.Cond{
			leaf("structured.service", "eq", "SSH"),
			leaf("structured.service", "eq", "RDP"),
			leaf("structured.service", "eq", "SMB"),
			leaf("structured.service", "eq", "TELNET"),
			leaf("structured.service", "eq", "MSSQL"),
		}},
	}}},

	// Privilege escalation via sudo.
	{"T1548", leaf("app_name", "eq", "sudo")},

	// SYN-flood / resource-exhaustion noted by the kernel.
	{"T1499", leaf("msg", "contains", "SYN flooding")},
}

// Map returns the sorted, de-duplicated technique IDs that match rec. It is
// safe for concurrent use (the detection table is read-only).
func Map(rec rules.Record) []string {
	var hits []string
	seen := map[string]bool{}
	for _, d := range detections {
		if seen[d.technique] {
			continue
		}
		if d.cond.Match(rec) {
			seen[d.technique] = true
			hits = append(hits, d.technique)
		}
	}
	sort.Strings(hits)
	return hits
}

// catalog is assembled once; the slices above never change at runtime.
var catalog = Catalog{Tactics: tactics, Techniques: techniques}

// Get returns the technique catalog served at /api/mitre.
func Get() Catalog { return catalog }
