package preset

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// renderWithin fails the test if one render does not return in time. A
// runaway template cannot be stopped, so it is left to die with the process.
func renderWithin(t *testing.T, p *Preset, d time.Duration) (string, error) {
	t.Helper()
	type result struct {
		msg string
		err error
	}
	ch := make(chan result, 1)
	go func() {
		msg, err := p.NewRenderer(RenderOpts{Facility: -1}).Render()
		ch <- result{msg, err}
	}()
	select {
	case r := <-ch:
		return r.msg, r.err
	case <-time.After(d):
		t.Fatalf("render still running after %s", d)
		return "", nil
	}
}

func TestOverflowingWeightsRejected(t *testing.T) {
	raw := fmt.Sprintf("name: w\nevents:\n  - weight: %d\n    template: a\n  - weight: %d\n    template: b\n",
		math.MaxInt, math.MaxInt)
	if _, err := Parse([]byte(raw)); err == nil {
		t.Fatal("weights whose sum overflows were accepted")
	}
}

func TestLargeValidWeightsKeepWorking(t *testing.T) {
	raw := "name: w\nevents:\n  - weight: 5000000\n    template: a\n  - weight: 2000000\n    template: b\n"
	p, err := Parse([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.NewRenderer(RenderOpts{Facility: -1}).Render(); err != nil {
		t.Fatal(err)
	}
}

func TestTemplateLoopsAreBounded(t *testing.T) {
	double := `{{define "a0"}}x{{end}}`
	for i := 1; i <= 40; i++ {
		double += fmt.Sprintf(`{{define "a%d"}}{{template "a%d"}}{{template "a%d"}}{{end}}`, i, i-1, i-1)
	}
	for name, tmpl := range map[string]string{
		"range":     `{{range 9000000000000}}{{end}}`,
		"nested":    `{{range 100000}}{{range 100000}}{{range 100000}}{{end}}{{end}}{{end}}`,
		"recursion": `{{define "r"}}{{template "r"}}{{end}}{{template "r"}}`,
		"fanout":    double + `{{template "a40"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := renderWithin(t, parseOne(t, tmpl), 20*time.Second); err == nil {
				t.Fatal("runaway template rendered without an error")
			}
		})
	}
}

func TestTemplateStringGrowthIsBounded(t *testing.T) {
	grow := func(expr string) string {
		return `{{$s := "aaaaaaaa"}}{{range 40}}{{$s = ` + expr + `}}{{end}}{{len $s}}`
	}
	for name, tmpl := range map[string]string{
		"printf":   grow(`printf "%s%s" $s $s`),
		"repeat":   grow(`printf "%[1]s%[1]s" $s`),
		"print":    grow(`print $s $s`),
		"println":  grow(`println $s $s`),
		"html":     `{{$s := "<<<<<<<<"}}{{range 100000}}{{$s = html $s}}{{end}}{{len $s}}`,
		"js":       `{{$s := "<<<<<<<<"}}{{range 40}}{{$s = js $s}}{{end}}{{len $s}}`,
		"urlquery": `{{$s := "<<<<<<<<"}}{{range 100000}}{{$s = urlquery $s}}{{end}}{{len $s}}`,
		"width":    `{{len (printf "` + strings.Repeat("%1000000d", 2000) + `" 1)}}`,
		"star":     `{{len (printf "` + strings.Repeat("%*d", 2000) + `" ` + strings.Repeat("1000000 1 ", 2000) + `)}}`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := renderWithin(t, parseOne(t, tmpl), 20*time.Second); err == nil {
				t.Fatal("unbounded string growth rendered without an error")
			}
		})
	}
}

// Templates that were valid before the limits must render the same.
func TestOrdinaryTemplateSyntaxKeepsWorking(t *testing.T) {
	for tmpl, want := range map[string]string{
		`{{range 3}}x{{end}}`:                                        "xxx",
		`{{range $i := 3}}{{$i}}{{end}}`:                             "012",
		`{{range 5}}{{if true}}y{{break}}{{end}}{{end}}`:             "y",
		`{{$s := "a"}}{{range 3}}{{$s = print $s "b"}}{{end}}{{$s}}`: "abbb",
		`{{printf "%05d|%-4s|%x" 42 "ab" "hi"}}`:                     "00042|ab  |6869",
		`x{{printf "%*d" 4 7}}`:                                      "x   7",
		`{{print "a" 1 2 "b"}}`:                                      "a1 2b",
		`{{html "<a>"}} {{js "it's"}} {{urlquery "a b"}}`:            `&lt;a&gt; it\'s a+b`,
		`{{define "t"}}in{{end}}{{template "t"}}`:                    "in",
		`{{with "v"}}{{.}}{{end}}`:                                   "v",
	} {
		msg, err := renderWithin(t, parseOne(t, tmpl), 5*time.Second)
		if err != nil {
			t.Errorf("%s: %v", tmpl, err)
			continue
		}
		if got := strings.TrimPrefix(msg, "<134>"); got != want {
			t.Errorf("%s: got %q, want %q", tmpl, got, want)
		}
	}
}

// A loop that emits output is limited by the render cap, not cut off sooner.
func TestLoopUpToRenderCapKeepsWorking(t *testing.T) {
	msg, err := renderWithin(t, parseOne(t, fmt.Sprintf(`{{range %d}}x{{end}}`, maxRendered)), 20*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(msg) - len("<134>"); got != maxRendered {
		t.Fatalf("rendered %d bytes, want %d", got, maxRendered)
	}
}

func customYAML(name, body string) []byte {
	return []byte(fmt.Sprintf("name: %q\nevents:\n  - template: %s\n", name, body))
}

func TestSaveRejectsNameSharingAFile(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Save(customYAML("my.fw", "first")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Save(customYAML("my-fw", "second")); err == nil {
		t.Fatal("a name mapping to another preset's file was accepted")
	}
	if _, ok := s.Get("my-fw"); ok {
		t.Fatal("rejected preset is still listed")
	}
	if _, err := s.Save(customYAML("my.fw", "edited")); err != nil {
		t.Fatalf("re-saving a preset under its own name: %v", err)
	}
	again, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	p, ok := again.Get("my.fw")
	if !ok || p.Events[0].Template != "edited" {
		t.Fatalf("my.fw after restart: %+v, %v", p, ok)
	}
}

// Files keep working under whatever name they already have on disk: editing
// or deleting one preset must never touch the file backing another.
func TestExistingFilesStayWithTheirPreset(t *testing.T) {
	dir := t.TempDir()
	for file, name := range map[string]string{"my-fw.yaml": "my.fw", "other.yml": "my-fw"} {
		if err := os.WriteFile(filepath.Join(dir, file), customYAML(name, "orig"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Save(customYAML("my-fw", "edited")); err != nil {
		t.Fatalf("editing a preset loaded from its own file: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "my-fw.yaml"))
	if err != nil || !strings.Contains(string(raw), "orig") {
		t.Fatalf("my.fw's file was overwritten: %q, %v", raw, err)
	}
	if err := s.Delete("my-fw"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "my-fw.yaml")); err != nil {
		t.Fatalf("deleting my-fw removed my.fw's file: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "other.yml")); !os.IsNotExist(err) {
		t.Fatalf("my-fw's own file was not removed: %v", err)
	}
}
