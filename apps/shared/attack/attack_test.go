package attack

import "testing"

// The catalog is data; the test guards its internal consistency so a hand
// edit can't introduce a dangling tactic reference or a duplicate ID.
func TestCatalogConsistency(t *testing.T) {
	shorts := map[string]bool{}
	for _, ta := range Tactics {
		if shorts[ta.Short] {
			t.Errorf("duplicate tactic short %q", ta.Short)
		}
		shorts[ta.Short] = true
	}
	seen := map[string]bool{}
	for _, tech := range Techniques {
		if seen[tech.ID] {
			t.Errorf("duplicate technique %s", tech.ID)
		}
		seen[tech.ID] = true
		if len(tech.Tactics) == 0 {
			t.Errorf("%s has no tactics", tech.ID)
		}
		for _, s := range tech.Tactics {
			if !shorts[s] {
				t.Errorf("%s references unknown tactic %q", tech.ID, s)
			}
		}
		if tech.URL == "" {
			t.Errorf("%s has no reference URL", tech.ID)
		}
		if got, ok := Lookup(tech.ID); !ok || got.ID != tech.ID {
			t.Errorf("Lookup(%s) = %+v, %v", tech.ID, got, ok)
		}
	}
	if _, ok := Lookup("T0000"); ok {
		t.Error("Lookup of unknown ID reported ok")
	}
}
