package parsers

import (
	"regexp"
	"strings"

	"github.com/syslog-yard/syslog-bucket/internal/store"
)

// FortiGate parses FortiOS key=value logs. FortiGates send them as a bare
// "<PRI>date=… time=… devname=… devid=… logid=…" line with no syslog
// header, so the wire-level host is only the sender's address; the device
// names itself in devname. Every pair (logid, devid, type, subtype, vd, …)
// lands in Structured.
type FortiGate struct{}

func (FortiGate) Name() string { return "fortigate" }

func (FortiGate) Match(e *store.Entry) bool {
	if !strings.Contains(e.Msg, "logid=") {
		return false
	}
	// Serial prefixes: FG (FortiGate, FortiGate-VM), FW (FortiWiFi).
	dev := kvValuePrefix(e.Msg, "devid=", 2)
	return dev == "FG" || dev == "FW"
}

func (FortiGate) Normalize(e *store.Entry) {
	fields := extractKV(e.Msg)
	mergeStructured(e, fields)
	if name := fields["devname"]; name != "" {
		e.Host = name
	}
	e.AppName = "fortigate"
}

// SonicWall parses SonicOS "id=firewall sn=… time=… fw=… pri=… m=…" logs,
// which also arrive without a syslog header. They carry no device name (fw=
// is the WAN address), so only the app is set.
type SonicWall struct{}

func (SonicWall) Name() string { return "sonicwall" }

func (SonicWall) Match(e *store.Entry) bool {
	return strings.HasPrefix(e.Msg, "id=") && strings.Contains(e.Msg, " sn=") && strings.Contains(e.Msg, " fw=")
}

func (SonicWall) Normalize(e *store.Entry) {
	mergeStructured(e, extractKV(e.Msg))
	e.AppName = "sonicwall"
}

// panosRe matches the head of a PAN-OS CSV log: FUTURE_USE, receive time,
// serial number, type, subtype.
var panosRe = regexp.MustCompile(`^\d+,(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}),([^,]*),([A-Z]+),([^,]*),`)

// PANOS parses PAN-OS CSV logs, whose syslog header has a host but no
// program name (the CSV record follows the host directly).
type PANOS struct{}

func (PANOS) Name() string { return "panos" }

func (PANOS) Match(e *store.Entry) bool { return panosRe.MatchString(e.Msg) }

func (PANOS) Normalize(e *store.Entry) {
	m := panosRe.FindStringSubmatch(e.Msg)
	if m == nil {
		return
	}
	fields := map[string]string{"receive_time": m[1], "serial": m[2], "type": m[3]}
	if m[4] != "" {
		fields["subtype"] = m[4]
	}
	mergeStructured(e, fields)
	e.AppName = "panos"
}

// kvValuePrefix returns up to n bytes of the value of key (given with its
// "="), skipping an opening quote, when key starts a token in msg.
func kvValuePrefix(msg, key string, n int) string {
	for i := 0; ; {
		j := strings.Index(msg[i:], key)
		if j < 0 {
			return ""
		}
		j += i
		if j == 0 || msg[j-1] == ' ' || msg[j-1] == '\t' {
			v := strings.TrimPrefix(msg[j+len(key):], `"`)
			return v[:min(n, len(v))]
		}
		i = j + len(key)
	}
}
