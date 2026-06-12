// Package frameworks adds compliance/standards views on top of the suite's
// existing detections. Rather than re-detecting events, a framework is a
// curated *crosswalk*: each framework item lists the MITRE ATT&CK techniques
// and Claroty OT alert codes that map onto it. So the views aggregate the
// counts the bucket already computes (entries.mitre / entries.ot), and
// drilling into an item expands to a filter over those same tags — no extra
// per-entry storage.
//
// The crosswalks are opinionated and deliberately coarse (like the mitre
// detection table): enough to give an analyst a standards-aligned overview of
// what the sensors are seeing, not an audit-grade control assessment. Adding
// another framework is just another entry in All().
package frameworks

// Group is a column in a framework's matrix view (a top-level grouping).
type Group struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Item is one framework control/category (a cell), with the technique/alert
// codes that map onto it.
type Item struct {
	ID    string   `json:"id"`
	Name  string   `json:"name"`
	Group string   `json:"group"`           // Group.ID this cell sits under
	Mitre []string `json:"mitre,omitempty"` // ATT&CK technique IDs that satisfy it
	OT    []string `json:"ot,omitempty"`    // Claroty OT alert codes that satisfy it
}

// Framework is one standard the bucket can present.
type Framework struct {
	ID     string  `json:"id"`
	Name   string  `json:"name"`
	Short  string  `json:"short"`
	Desc   string  `json:"desc"`
	Groups []Group `json:"groups"`
	Items  []Item  `json:"items"`
}

var all = []Framework{nistCSF, cisV8, iec62443}

// All returns every framework catalog, served at /api/frameworks.
func All() []Framework { return all }

// Get returns one framework by ID.
func Get(id string) (Framework, bool) {
	for _, f := range all {
		if f.ID == id {
			return f, true
		}
	}
	return Framework{}, false
}

// Expand returns the MITRE technique IDs and OT alert codes a framework item
// covers, for building an entry filter. ok=false for an unknown framework/item.
func Expand(fwID, itemID string) (mitre []string, ot []string, ok bool) {
	f, found := Get(fwID)
	if !found {
		return nil, nil, false
	}
	for _, it := range f.Items {
		if it.ID == itemID {
			return it.Mitre, it.OT, true
		}
	}
	return nil, nil, false
}

// ---- catalogs --------------------------------------------------------------

// NIST Cybersecurity Framework 2.0 — Functions as columns, Categories as cells.
var nistCSF = Framework{
	ID: "nist-csf", Name: "NIST CSF 2.0", Short: "NIST CSF",
	Desc: "Cybersecurity Framework functions & categories",
	Groups: []Group{
		{"GV", "Govern"}, {"ID", "Identify"}, {"PR", "Protect"}, {"DE", "Detect"}, {"RS", "Respond"},
	},
	Items: []Item{
		{ID: "GV.PO", Name: "Policy", Group: "GV", OT: []string{"CL-POL"}},
		{ID: "ID.AM", Name: "Asset Management", Group: "ID", OT: []string{"CL-NEWA", "CL-CHG"}},
		{ID: "PR.AA", Name: "Identity & Access Control", Group: "PR", Mitre: []string{"T1110", "T1078", "T1021", "T1548"}, OT: []string{"CL-UA"}},
		{ID: "PR.PS", Name: "Platform Security", Group: "PR", Mitre: []string{"T1190"}, OT: []string{"CL-CFG", "CL-MODE"}},
		{ID: "PR.AT", Name: "Awareness & Training", Group: "PR", Mitre: []string{"T1204", "T1566"}},
		{ID: "DE.CM", Name: "Continuous Monitoring", Group: "DE", Mitre: []string{"T1190", "T1110", "T1021"}, OT: []string{"CL-SCAN", "CL-KT", "CL-MAL"}},
		{ID: "DE.AE", Name: "Adverse Event Analysis", Group: "DE", Mitre: []string{"T1071", "T1078", "T1548", "T1499"}, OT: []string{"CL-SUS", "CL-BASE", "CL-CONF"}},
		{ID: "RS.AN", Name: "Incident Analysis", Group: "RS", Mitre: []string{"T1071"}, OT: []string{"CL-KT", "CL-MAL"}},
		{ID: "RS.MI", Name: "Mitigation", Group: "RS", Mitre: []string{"T1499"}},
	},
}

// CIS Controls v8 — grouped by the NIST function each control most serves.
var cisV8 = Framework{
	ID: "cis-v8", Name: "CIS Controls v8", Short: "CIS",
	Desc: "CIS Critical Security Controls",
	Groups: []Group{
		{"identify", "Identify"}, {"protect", "Protect"}, {"detect", "Detect"}, {"respond", "Respond"},
	},
	Items: []Item{
		{ID: "CIS-1", Name: "1 · Enterprise Asset Inventory", Group: "identify", OT: []string{"CL-NEWA", "CL-CHG"}},
		{ID: "CIS-4", Name: "4 · Secure Configuration", Group: "protect", Mitre: []string{"T1190"}, OT: []string{"CL-CFG", "CL-MODE"}},
		{ID: "CIS-5", Name: "5 · Account Management", Group: "protect", Mitre: []string{"T1078"}, OT: []string{"CL-UA"}},
		{ID: "CIS-6", Name: "6 · Access Control Management", Group: "protect", Mitre: []string{"T1110", "T1021", "T1548"}},
		{ID: "CIS-9", Name: "9 · Email & Web Protections", Group: "protect", Mitre: []string{"T1566", "T1204"}},
		{ID: "CIS-8", Name: "8 · Audit Log Management", Group: "detect", Mitre: []string{"T1078", "T1190"}},
		{ID: "CIS-10", Name: "10 · Malware Defenses", Group: "detect", Mitre: []string{"T1204"}, OT: []string{"CL-MAL", "CL-KT"}},
		{ID: "CIS-13", Name: "13 · Network Monitoring & Defense", Group: "detect", Mitre: []string{"T1071", "T1499"}, OT: []string{"CL-SCAN", "CL-SUS", "CL-BASE"}},
		{ID: "CIS-17", Name: "17 · Incident Response Management", Group: "respond", Mitre: []string{"T1499"}, OT: []string{"CL-CONF"}},
	},
}

// IEC 62443-3-3 — the seven Foundational Requirements, grouped into themes.
// OT-centric, so primarily fed by the Claroty alert codes.
var iec62443 = Framework{
	ID: "iec62443", Name: "IEC 62443-3-3", Short: "IEC 62443",
	Desc: "Foundational Requirements for IACS security",
	Groups: []Group{
		{"access", "Access & Use Control"}, {"integrity", "System & Data Integrity"}, {"monitor", "Monitoring & Availability"},
	},
	Items: []Item{
		{ID: "FR1", Name: "FR1 · Identification & Authentication Control", Group: "access", Mitre: []string{"T1078", "T1110"}, OT: []string{"CL-UA"}},
		{ID: "FR2", Name: "FR2 · Use Control", Group: "access", Mitre: []string{"T1548"}, OT: []string{"CL-POL", "CL-CFG", "CL-MODE"}},
		{ID: "FR3", Name: "FR3 · System Integrity", Group: "integrity", Mitre: []string{"T1190"}, OT: []string{"CL-KT", "CL-MAL", "CL-CFG", "CL-MODE"}},
		{ID: "FR4", Name: "FR4 · Data Confidentiality", Group: "integrity", OT: []string{"CL-SUS"}},
		{ID: "FR5", Name: "FR5 · Restricted Data Flow", Group: "monitor", Mitre: []string{"T1021", "T1071"}, OT: []string{"CL-BASE", "CL-SCAN"}},
		{ID: "FR6", Name: "FR6 · Timely Response to Events", Group: "monitor", Mitre: []string{"T1190"}, OT: []string{"CL-KT", "CL-SUS", "CL-NEWA", "CL-CONF"}},
		{ID: "FR7", Name: "FR7 · Resource Availability", Group: "monitor", Mitre: []string{"T1499"}, OT: []string{"CL-CONF"}},
	},
}
