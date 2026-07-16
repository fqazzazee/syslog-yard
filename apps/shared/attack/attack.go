// Package attack is the suite's single copy of the MITRE ATT&CK catalog:
// the tactics and the curated technique slice both the valve and the bucket
// recognise. Detection stays app-specific — the bucket matches parsed
// structured fields via its rules AST, the valve matches the raw line via
// syslog-ng patterns — but the vocabulary (IDs, names, tactic membership)
// lives here so the two tools can never drift apart again.
package attack

// Tactic is one ATT&CK tactic (a kill-chain column). Order follows the
// Enterprise matrix left-to-right so UIs can lay tactics out in sequence.
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

// Tactics in ATT&CK Enterprise matrix order (only the ones our techniques use).
var Tactics = []Tactic{
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

// Techniques this build recognises. Every entry has a detection in the
// bucket (internal/mitre detections) and a wire pattern in the valve
// (internal/mitre patterns); add all three together.
var Techniques = []Technique{
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

var byID = func() map[string]Technique {
	m := make(map[string]Technique, len(Techniques))
	for _, t := range Techniques {
		m[t.ID] = t
	}
	return m
}()

// Lookup returns the technique for an ID and whether it is known.
func Lookup(id string) (Technique, bool) {
	t, ok := byID[id]
	return t, ok
}
