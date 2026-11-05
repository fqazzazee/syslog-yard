package preset

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func parseOne(t *testing.T, tmpl string) *Preset {
	t.Helper()
	p, err := Parse([]byte(fmt.Sprintf(`
name: limits
vendor: Test
format: raw
facility: 16
events:
  - weight: 1
    severity: 6
    template: %q
`, tmpl)))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRandHexIsClamped(t *testing.T) {
	msg, err := parseOne(t, `{{randHex 100000000}}`).NewRenderer(RenderOpts{Facility: -1}).Render()
	if err != nil {
		t.Fatal(err)
	}
	if got := len(msg) - len("<134>"); got != maxRandHex {
		t.Fatalf("randHex produced %d chars, want %d", got, maxRandHex)
	}
	msg, err = parseOne(t, `x{{randHex -5}}`).NewRenderer(RenderOpts{Facility: -1}).Render()
	if err != nil || msg != "<134>x" {
		t.Fatalf("negative randHex: %q, %v", msg, err)
	}
}

func TestRenderOutputIsCapped(t *testing.T) {
	tmpl := strings.Repeat(`{{randHex 1024}}`, 100) // 100 KiB
	_, err := parseOne(t, tmpl).NewRenderer(RenderOpts{Facility: -1}).Render()
	if !errors.Is(err, errRenderTooLong) {
		t.Fatalf("expected a size error, got %v", err)
	}
}

func TestSeqNamesBounded(t *testing.T) {
	r := parseOne(t, `{{seq (randHex 12)}}`).NewRenderer(RenderOpts{Facility: -1})
	for i := 0; i < 2000; i++ {
		if _, err := r.Render(); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(r.seqs); n > maxSeqNames {
		t.Fatalf("seq map grew to %d names", n)
	}
}
