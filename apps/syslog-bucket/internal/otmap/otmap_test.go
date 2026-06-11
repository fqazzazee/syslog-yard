package otmap_test

import (
	"reflect"
	"testing"

	"github.com/syslog-yard/syslog-bucket/internal/otmap"
	"github.com/syslog-yard/syslog-bucket/internal/store"
)

// entry builds a store.Entry (a rules.Record) carrying a CEF message — the
// shape Claroty CTD/xDome emit and syslog-hose generates.
func entry(msg string) *store.Entry { return &store.Entry{AppName: "CTD", Msg: msg} }

func TestMapClarotyCEF(t *testing.T) {
	cases := []struct {
		name string
		msg  string
		want []string
	}{
		{"known threat", "CEF:0|Claroty|CTD|4.12.1|CL-KT|Known Threat|9|cat=Security src=10.0.0.5 msg=threat intel match", []string{"CL-KT"}},
		{"suspicious", "CEF:0|Claroty|CTD|4.12.1|CL-SUS|Suspicious Activity|7|cat=Security msg=odd write", []string{"CL-SUS"}},
		{"scan", "CEF:0|Claroty|xDome|2.9|CL-SCAN|Network Scan|6|cat=Security msg=sweep", []string{"CL-SCAN"}},
		{"unauthorized", "CEF:0|Claroty|CTD|4.12.1|CL-UA|Unauthorized Access|7|cat=Security msg=login", []string{"CL-UA"}},
		{"policy", "CEF:0|Claroty|xDome|2.9|CL-POL|Policy Violation|6|cat=Security msg=cleartext", []string{"CL-POL"}},
		{"malware", "CEF:0|Claroty|xDome|2.9|CL-MAL|Malware / Exploit|8|cat=Security msg=exploit", []string{"CL-MAL"}},
		{"new asset", "CEF:0|Claroty|CTD|4.12.1|CL-NEWA|New Asset|4|cat=Integrity msg=discovered", []string{"CL-NEWA"}},
		{"asset change", "CEF:0|Claroty|xDome|2.9|CL-CHG|Asset Change|5|cat=Integrity msg=firmware", []string{"CL-CHG"}},
		{"baseline", "CEF:0|Claroty|CTD|4.12.1|CL-BASE|Baseline Deviation|5|cat=Integrity msg=new conv", []string{"CL-BASE"}},
		{"config download", "CEF:0|Claroty|CTD|4.12.1|CL-CFG|Configuration Download|6|cat=Integrity msg=code download", []string{"CL-CFG"}},
		{"plc mode", "CEF:0|Claroty|CTD|4.12.1|CL-MODE|PLC Mode Change|6|cat=Integrity msg=run to program", []string{"CL-MODE"}},
		{"conflict", "CEF:0|Claroty|CTD|4.12.1|CL-CONF|IP/MAC Conflict|5|cat=Integrity msg=dup ip", []string{"CL-CONF"}},
		{"non-claroty", "Administrator login failed", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := otmap.Map(entry(tc.msg))
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("Map() = %v, want %v", got, tc.want)
			}
		})
	}
}

// Every alert type belongs to a known category and has a detection.
func TestCatalogConsistency(t *testing.T) {
	cat := otmap.Get()
	shorts := map[string]bool{}
	for _, c := range cat.Categories {
		shorts[c.Short] = true
	}
	for _, a := range cat.AlertTypes {
		if len(a.Categories) == 0 {
			t.Errorf("alert %s has no category", a.ID)
		}
		for _, s := range a.Categories {
			if !shorts[s] {
				t.Errorf("alert %s references unknown category %q", a.ID, s)
			}
		}
		// the alert type's Name must be detectable as a "|Name|" token.
		if otmap.Map(entry("CEF:0|Claroty|CTD|1|"+a.ID+"|"+a.Name+"|5|cat=x")) == nil {
			t.Errorf("alert %s (%q) has no working detection", a.ID, a.Name)
		}
	}
}
