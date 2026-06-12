package frameworks_test

import (
	"testing"

	"github.com/syslog-yard/syslog-bucket/internal/classify"
	"github.com/syslog-yard/syslog-bucket/internal/frameworks"
	"github.com/syslog-yard/syslog-bucket/internal/mitre"
	"github.com/syslog-yard/syslog-bucket/internal/otmap"
)

// Every framework item must reference a real group and only known mitre/ot
// codes (or device classes) — otherwise its column won't render or its counts
// stay silently zero.
func TestCrosswalkIntegrity(t *testing.T) {
	techniques := map[string]bool{}
	for _, tch := range mitre.Get().Techniques {
		techniques[tch.ID] = true
	}
	alerts := map[string]bool{}
	for _, a := range otmap.Get().AlertTypes {
		alerts[a.ID] = true
	}
	classes := map[string]bool{
		classify.Firewall: true, classify.Network: true, classify.Host: true,
		classify.Windows: true, classify.OT: true,
	}

	for _, f := range frameworks.All() {
		groups := map[string]bool{}
		for _, g := range f.Groups {
			groups[g.ID] = true
		}
		if len(f.Items) == 0 {
			t.Errorf("%s has no items", f.ID)
		}
		for _, it := range f.Items {
			if !groups[it.Group] {
				t.Errorf("%s/%s references unknown group %q", f.ID, it.ID, it.Group)
			}
			if len(it.Mitre) == 0 && len(it.OT) == 0 && len(it.Class) == 0 {
				t.Errorf("%s/%s maps to nothing", f.ID, it.ID)
			}
			for _, m := range it.Mitre {
				if !techniques[m] {
					t.Errorf("%s/%s references unknown technique %q", f.ID, it.ID, m)
				}
			}
			for _, o := range it.OT {
				if !alerts[o] {
					t.Errorf("%s/%s references unknown OT code %q", f.ID, it.ID, o)
				}
			}
			for _, c := range it.Class {
				if !classes[c] {
					t.Errorf("%s/%s references unknown device class %q", f.ID, it.ID, c)
				}
			}
			m, o, c, ok := frameworks.Expand(f.ID, it.ID)
			if !ok || (len(m)+len(o)+len(c) == 0) {
				t.Errorf("Expand(%s,%s) failed", f.ID, it.ID)
			}
		}
	}
}
