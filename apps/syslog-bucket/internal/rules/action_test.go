package rules

import "testing"

func TestValidateActions(t *testing.T) {
	cases := []struct {
		name    string
		actions []Action
		ok      bool
	}{
		{"empty", nil, false},
		{"tag ok", []Action{{Type: "tag", TagID: 3}}, true},
		{"tag missing id", []Action{{Type: "tag"}}, false},
		{"priority range", []Action{{Type: "set_priority", Priority: 4}}, false},
		{"suppress", []Action{{Type: "suppress"}}, true},
		{"notify needs channel", []Action{{Type: "notify"}}, false},
		{"set_mitre ok", []Action{{Type: "set_mitre", Mitre: []string{"T1110"}}}, true},
		{"set_mitre empty", []Action{{Type: "set_mitre"}}, false},
		{"set_ot ok", []Action{{Type: "set_ot", OT: []string{"CL-KT"}}}, true},
		{"set_ot empty", []Action{{Type: "set_ot"}}, false},
		{"unknown type", []Action{{Type: "frobnicate"}}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateActions(c.actions)
			if (err == nil) != c.ok {
				t.Fatalf("ValidateActions(%v) error = %v, want ok=%v", c.actions, err, c.ok)
			}
		})
	}
}
