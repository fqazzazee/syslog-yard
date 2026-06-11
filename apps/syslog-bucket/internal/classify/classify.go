// Package classify derives a coarse device class for an entry from its app
// name (suite S8). The class is a first-class, sortable/filterable column —
// it lets an analyst pull "all firewall events" or "all host events" without
// knowing every vendor's app name. It is intentionally coarse; vendor-level
// detail stays in app_name and the parsed structured fields.
package classify

import "strings"

// Classes returned by Class. "" means unknown (rendered as "—" in the UI).
const (
	Firewall = "firewall"
	Network  = "network"
	Host     = "host"
	Windows  = "windows"
	OT       = "ot"
)

// appHints maps an app-name substring to a device class, longest-intent
// first. Matching is case-insensitive substring containment so
// "fortigate", "FGT-asa" and "asa" all land sensibly.
var appHints = []struct {
	sub   string
	class string
}{
	{"fortigate", Firewall}, {"asa", Firewall}, {"panos", Firewall}, {"palo", Firewall},
	{"srx", Firewall}, {"sonicwall", Firewall}, {"checkpoint", Firewall}, {"barracuda", Firewall},
	{"pfsense", Firewall}, {"opnsense", Firewall}, {"filterlog", Firewall},
	{"mikrotik", Network}, {"unifi", Network}, {"routeros", Network}, {"switch", Network},
	{"moxa", OT}, {"hirschmann", OT}, {"plc", OT}, {"scada", OT},
	{"snare", Windows}, {"nxlog", Windows}, {"microsoft-windows", Windows}, {"winlogon", Windows},
	{"sshd", Host}, {"sudo", Host}, {"cron", Host}, {"systemd", Host},
	{"kernel", Host}, {"pam_unix", Host},
}

// msgHints catch vendors whose raw key=value lines don't carry a clean
// program name (so app_name parses to noise) — we fall back to a stable
// signature in the message text. Matched case-insensitively.
var msgHints = []struct {
	sub   string
	class string
}{
	{`devid="fgt`, Firewall}, // FortiGate
	{"%asa-", Firewall},      // Cisco ASA
	{"%pan-", Firewall},      // Palo Alto PAN-OS
	{"filterlog", Firewall},  // pfSense/OPNsense
	{"rt_flow", Firewall},    // Juniper SRX
}

// Class returns the device class for an entry, derived first from its app
// name and then, as a fallback, from a signature in the message. "" means
// unknown.
func Class(appName, msg string) string {
	a := strings.ToLower(strings.TrimSpace(appName))
	for _, h := range appHints {
		if strings.Contains(a, h.sub) {
			return h.class
		}
	}
	m := strings.ToLower(msg)
	for _, h := range msgHints {
		if strings.Contains(m, h.sub) {
			return h.class
		}
	}
	return ""
}
