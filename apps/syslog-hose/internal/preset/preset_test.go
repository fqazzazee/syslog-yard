package preset

import (
	"regexp"
	"strings"
	"testing"
)

// Every builtin must load, render without template errors, and produce a
// syslog line that starts with a valid PRI.
func TestBuiltinsRender(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("loading builtins: %v", err)
	}
	all := store.List()
	if len(all) != 17 {
		t.Fatalf("expected 17 builtin presets, got %d", len(all))
	}
	pri := regexp.MustCompile(`^<(\d{1,3})>`)
	for _, p := range all {
		r := p.NewRenderer(RenderOpts{Facility: -1})
		seen := map[string]bool{}
		for i := 0; i < 200; i++ {
			msg, err := r.Render()
			if err != nil {
				t.Fatalf("%s: render: %v", p.Name, err)
			}
			m := pri.FindStringSubmatch(msg)
			if m == nil {
				t.Fatalf("%s: message lacks <PRI> prefix: %q", p.Name, msg)
			}
			if strings.ContainsAny(msg, "\n") {
				t.Fatalf("%s: message contains newline: %q", p.Name, msg)
			}
			if len(msg) < 20 {
				t.Fatalf("%s: suspiciously short message: %q", p.Name, msg)
			}
			seen[msg] = true
		}
		if len(seen) < 50 {
			t.Errorf("%s: only %d distinct messages out of 200 — not random enough", p.Name, len(seen))
		}
	}
}

func TestFormats(t *testing.T) {
	raw := []byte(`
name: t
vendor: Test
format: rfc3164
facility: 16
appname: testapp
events:
  - weight: 1
    severity: 6
    template: "hello world"
`)
	p, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]*regexp.Regexp{
		"rfc3164": regexp.MustCompile(`^<134>[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2} myhost testapp\[\d+\]: hello world$`),
		"rfc5424": regexp.MustCompile(`^<134>1 \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}[+-]\d{2}:\d{2} myhost testapp \d+ - - hello world$`),
		"raw":     regexp.MustCompile(`^<134>hello world$`),
	}
	for format, want := range cases {
		r := p.NewRenderer(RenderOpts{Hostname: "myhost", Facility: -1, Format: format})
		msg, err := r.Render()
		if err != nil {
			t.Fatalf("%s: %v", format, err)
		}
		if !want.MatchString(msg) {
			t.Errorf("%s: got %q, want match %q", format, msg, want)
		}
	}
}

func TestCustomPresetLifecycle(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	yaml := []byte("name: my-custom\nvendor: Me\nformat: raw\nfacility: 16\nappname: x\nevents:\n  - weight: 1\n    severity: 6\n    template: \"src={{randIP \\\"rfc1918\\\"}}\"\n")
	if _, err := store.Save(yaml); err != nil {
		t.Fatalf("save: %v", err)
	}
	// reload from disk
	store2, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	p, ok := store2.Get("my-custom")
	if !ok {
		t.Fatal("custom preset did not survive reload")
	}
	if p.Builtin {
		t.Fatal("custom preset marked builtin")
	}
	if err := store2.Delete("my-custom"); err != nil {
		t.Fatal(err)
	}
	if err := store2.Delete("cisco-asa"); err == nil {
		t.Fatal("deleting a builtin should fail")
	}
	if _, err := store2.Save([]byte("name: cisco-asa\nevents:\n  - template: x\n")); err == nil {
		t.Fatal("overwriting a builtin should fail")
	}
}
