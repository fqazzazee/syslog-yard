package parsers

import (
	"encoding/json"
	"fmt"
	"maps"
	"strings"
	"testing"

	"github.com/syslog-yard/syslog-bucket/internal/store"
)

func TestExtractKV(t *testing.T) {
	cases := []struct {
		msg  string
		want map[string]string
	}{
		{"no pairs here", map[string]string{}},
		{"user=alice action=blocked", map[string]string{"user": "alice", "action": "blocked"}},
		{`msg="two words" src=10.0.0.1`, map[string]string{"msg": "two words", "src": "10.0.0.1"}},
		{"a=1,b=2\tc=3", map[string]string{"a": "1", "b": "2", "c": "3"}},
		{"dotted.key-name_1=v", map[string]string{"dotted.key-name_1": "v"}},
		{"=orphan x= y=", map[string]string{}},                           // no key, or no value
		{`k="" j=ok`, map[string]string{"j": "ok"}},                      // empty quoted value dropped
		{`k="unterminated j=ok`, map[string]string{"j": "ok"}},           // runaway quote skipped
		{"url=http://x/?a=b", map[string]string{"url": "http://x/?a=b"}}, // later '=' stays in the value
		{"dup=1 dup=2", map[string]string{"dup": "2"}},                   // last one wins
		{"prefix:key=v", map[string]string{"key": "v"}},                  // key stops at a non-key byte
		{`devname="FGT-1" devid="FGT60F" level=notice`, map[string]string{"devname": "FGT-1", "devid": "FGT60F", "level": "notice"}},
	}
	for _, c := range cases {
		if got := extractKV(c.msg); !maps.Equal(got, c.want) {
			t.Errorf("extractKV(%q) = %v, want %v", c.msg, got, c.want)
		}
	}
}

func TestExtractKVCapsKeys(t *testing.T) {
	var sb strings.Builder
	for i := range maxStructuredKeys + 20 {
		fmt.Fprintf(&sb, "k%d=v ", i)
	}
	if got := extractKV(sb.String()); len(got) != maxStructuredKeys {
		t.Errorf("extracted %d keys, want the cap of %d", len(got), maxStructuredKeys)
	}
}

// Hostile input terminates and never panics.
func TestExtractKVEdgeInputs(t *testing.T) {
	for _, msg := range []string{"", "=", "==", `="`, `k="`, `k=" `, "k=", strings.Repeat("=", 1000), strings.Repeat(`a="`, 500)} {
		extractKV(msg)
	}
}

func TestGenericNormalizeMerges(t *testing.T) {
	e := store.Entry{Msg: "user=bob pid=999", Structured: json.RawMessage(`{"pid":"12","msgid":"ID1"}`)}
	Generic{}.Normalize(&e)
	var got map[string]string
	if err := json.Unmarshal(e.Structured, &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"user": "bob", "pid": "999", "msgid": "ID1"}
	if !maps.Equal(got, want) {
		t.Errorf("structured = %v, want %v", got, want)
	}

	// Nothing extracted: the existing value is left exactly as it was.
	e = store.Entry{Msg: "plain text", Structured: json.RawMessage(`{"pid":"12"}`)}
	Generic{}.Normalize(&e)
	if string(e.Structured) != `{"pid":"12"}` {
		t.Errorf("structured rewritten without new fields: %s", e.Structured)
	}
	e = store.Entry{Msg: "plain text"}
	Generic{}.Normalize(&e)
	if e.Structured != nil {
		t.Errorf("structured set without fields: %s", e.Structured)
	}
}

type fakeParser struct {
	name  string
	match bool
	ran   *[]string
}

func (p fakeParser) Name() string             { return p.name }
func (p fakeParser) Match(*store.Entry) bool  { return p.match }
func (p fakeParser) Normalize(e *store.Entry) { *p.ran = append(*p.ran, p.name) }

// The registry runs only the first parser that matches.
func TestRegistryFirstMatchWins(t *testing.T) {
	var ran []string
	r := NewRegistry(
		fakeParser{"skip", false, &ran},
		fakeParser{"vendor", true, &ran},
		fakeParser{"also", true, &ran},
	)
	r.Apply(&store.Entry{})
	if len(ran) != 1 || ran[0] != "vendor" {
		t.Errorf("ran %v, want [vendor]", ran)
	}
	NewRegistry().Apply(&store.Entry{}) // no parsers: a no-op, not a panic
	if g := (Generic{}); g.Name() != "generic" || !g.Match(&store.Entry{}) {
		t.Error("generic must be a catch-all named generic")
	}
}
