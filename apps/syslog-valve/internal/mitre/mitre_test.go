package mitre

import (
	"testing"

	"github.com/syslog-yard/shared/attack"
)

// Every pattern must point at a catalog technique, and — since the valve's
// technique filter should line up with what the bucket labels — every
// catalog technique should have a wire pattern here.
func TestPatternsMatchCatalog(t *testing.T) {
	for id, p := range patterns {
		if _, ok := attack.Lookup(id); !ok {
			t.Errorf("pattern for %s has no catalog entry", id)
		}
		if p.Message == "" && p.Program == "" {
			t.Errorf("pattern for %s matches nothing", id)
		}
	}
	for _, tech := range attack.Techniques {
		if _, ok := patterns[tech.ID]; !ok {
			t.Errorf("catalog technique %s has no wire pattern", tech.ID)
		}
	}
}

func TestLookup(t *testing.T) {
	tech, ok := Lookup("T1110")
	if !ok || tech.Name != "Brute Force" || tech.Message == "" {
		t.Fatalf("Lookup(T1110) = %+v, %v", tech, ok)
	}
	if _, ok := Lookup("T0000"); ok {
		t.Error("Lookup of unknown ID reported ok")
	}
}
