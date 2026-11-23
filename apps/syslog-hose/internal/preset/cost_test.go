package preset

import (
	"strings"
	"testing"
	"time"
)

// The budget has to hold for wide loop bodies too, where each pass does a lot
// of work, and for helpers that build strings without emitting them.
func TestWideLoopBodiesAreBounded(t *testing.T) {
	for name, body := range map[string]string{
		"randHex":  strings.Repeat(`{{$x := randHex 1024}}`, 2000),
		"uuid":     strings.Repeat(`{{$x := uuid}}`, 5000),
		"pipeline": `{{$x := 1` + strings.Repeat(` | or 1`, 20000) + `}}`,
	} {
		t.Run(name, func(t *testing.T) {
			start := time.Now()
			_, err := renderWithin(t, parseOne(t, `{{range 100000}}`+body+`{{end}}`), 120*time.Second)
			if err == nil {
				t.Fatal("runaway template rendered without an error")
			}
			t.Logf("stopped after %s", time.Since(start).Round(time.Millisecond))
		})
	}
}
