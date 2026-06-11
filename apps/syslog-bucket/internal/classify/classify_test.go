package classify

import "testing"

func TestClass(t *testing.T) {
	cases := []struct {
		app, msg, want string
	}{
		{"sshd", "Failed password", "host"},
		{"sudo", "x", "host"},
		{"fortigate", "anything", "firewall"},
		{"unifi", "x", "network"},
		// raw FortiGate whose tag parsed to noise — fall back to the message.
		{"date=2026-06-11", `time=04:54 devname="fw" devid="FGT60FTK2009012345" type="traffic"`, "firewall"},
		{"asa", "%ASA-6-302013: Built outbound", "firewall"},
		{"", "%ASA-4-106023: Deny tcp", "firewall"},
		{"nginx", "GET / 200", ""},
		{"", "", ""},
	}
	for _, c := range cases {
		if got := Class(c.app, c.msg); got != c.want {
			t.Errorf("Class(%q, %q) = %q, want %q", c.app, c.msg, got, c.want)
		}
	}
}
