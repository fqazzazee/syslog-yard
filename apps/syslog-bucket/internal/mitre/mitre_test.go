package mitre_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/syslog-yard/syslog-bucket/internal/mitre"
	"github.com/syslog-yard/syslog-bucket/internal/store"
)

// entry builds a store.Entry (a rules.Record) from app/msg/structured.
func entry(app, msg string, structured map[string]string) *store.Entry {
	b, _ := json.Marshal(structured)
	return &store.Entry{AppName: app, Msg: msg, Structured: b}
}

func TestMapDemoTraffic(t *testing.T) {
	cases := []struct {
		name string
		e    *store.Entry
		want []string
	}{
		{"sshd failed password", entry("sshd", "Failed password for root from 1.2.3.4 port 22 ssh2", nil), []string{"T1110"}},
		{"sshd accepted", entry("sshd", "Accepted publickey for deploy from 10.0.0.5 port 22 ssh2", nil), []string{"T1078"}},
		{"fortigate admin login failed", entry("fortigate", "Administrator login failed", map[string]string{"action": "login", "status": "failed"}), []string{"T1110"}},
		{"fortigate admin login success", entry("fortigate", "Administrator logged in", map[string]string{"action": "login", "status": "success"}), []string{"T1078"}},
		{"ips log4j rce", entry("fortigate", "applications3: Log4j attack detected", map[string]string{"subtype": "ips", "attack": "Log4j.Error.Log.Remote.Code.Execution"}), []string{"T1190"}},
		{"ips cobalt strike", entry("fortigate", "beacon", map[string]string{"subtype": "ips", "attack": "Backdoor.Cobalt.Strike.Beacon"}), []string{"T1071"}},
		{"av infected", entry("fortigate", "File is infected.", map[string]string{"subtype": "virus", "virus": "EICAR_TEST_FILE"}), []string{"T1204"}},
		{"webfilter phishing", entry("fortigate", "blocked", map[string]string{"subtype": "webfilter", "catdesc": "Phishing", "action": "blocked"}), []string{"T1566"}},
		{"firewall deny rdp", entry("fortigate", "deny", map[string]string{"action": "deny", "service": "RDP"}), []string{"T1021"}},
		{"sudo", entry("sudo", "jsmith : TTY=pts/0 ; USER=root ; COMMAND=/usr/bin/dnf update", nil), []string{"T1548"}},
		{"kernel syn flood", entry("kernel", "TCP: Possible SYN flooding on port 443. Sending cookies.", nil), []string{"T1499"}},
		{"benign traffic", entry("fortigate", "traffic forward", map[string]string{"action": "accept", "service": "HTTPS"}), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mitre.Map(tc.e)
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Map() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCatalogConsistency(t *testing.T) {
	cat := mitre.Get()
	shorts := map[string]bool{}
	for _, tac := range cat.Tactics {
		shorts[tac.Short] = true
	}
	for _, tech := range cat.Techniques {
		if len(tech.Tactics) == 0 {
			t.Errorf("technique %s has no tactic", tech.ID)
		}
		for _, s := range tech.Tactics {
			if !shorts[s] {
				t.Errorf("technique %s references unknown tactic %q", tech.ID, s)
			}
		}
	}
}
