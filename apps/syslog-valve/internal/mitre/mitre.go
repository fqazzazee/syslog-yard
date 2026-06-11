// Package mitre carries the ATT&CK techniques the valve can filter on (suite
// S8). Unlike the bucket — which maps techniques from fully parsed structured
// fields — the valve matches on the raw syslog line as it crosses syslog-ng,
// so each technique is expressed as a syslog-ng filter pattern (a PCRE over
// the message, and/or a program name).
//
// The technique list is intentionally kept in step with the bucket's
// (apps/syslog-bucket/internal/mitre): same IDs, names and tactics, so a flow
// the valve routes "by technique" lines up with how the bucket later labels
// the same events. Patterns target the demo vocabulary (FortiGate key=value,
// sshd/sudo text).
package mitre

// Tactic is one ATT&CK tactic; Short is the join key used by techniques.
type Tactic struct {
	ID    string `json:"id"`
	Short string `json:"short"`
	Name  string `json:"name"`
}

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

var techniques = []Technique{
	{ID: "T1190", Name: "Exploit Public-Facing Application", Tactics: []string{"initial-access"},
		Message: `Code\.Execution`},
	{ID: "T1110", Name: "Brute Force", Tactics: []string{"credential-access"},
		Message: `Failed password|status="failed"`},
	{ID: "T1078", Name: "Valid Accounts", Tactics: []string{"initial-access", "persistence", "privilege-escalation", "defense-evasion"},
		Message: `Accepted (password|publickey)|status="success"|AAA user.*Successful`},
	{ID: "T1204", Name: "User Execution", Tactics: []string{"execution"},
		Message: `subtype="virus"`},
	{ID: "T1566", Name: "Phishing", Tactics: []string{"initial-access"},
		Message: `catdesc="Phishing"`},
	{ID: "T1071", Name: "Application Layer Protocol", Tactics: []string{"command-and-control"},
		Message: `Cobalt`},
	{ID: "T1021", Name: "Remote Services", Tactics: []string{"lateral-movement"},
		Message: `action="deny".*service="(SSH|RDP|SMB|TELNET|MSSQL)"`},
	{ID: "T1548", Name: "Abuse Elevation Control Mechanism", Tactics: []string{"privilege-escalation", "defense-evasion"},
		Program: "sudo"},
	{ID: "T1499", Name: "Endpoint Denial of Service", Tactics: []string{"impact"},
		Message: "SYN flooding"},
}

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
func Get() Catalog { return Catalog{Tactics: tactics, Techniques: techniques} }
