package rules

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// fakeRec implements Record for tests.
type fakeRec struct {
	fields map[string]any
	tags   map[int64]bool
}

func (f fakeRec) FieldValue(name string) (any, bool) {
	v, ok := f.fields[name]
	return v, ok
}
func (f fakeRec) HasTag(id int64) bool { return f.tags[id] }

func rec() fakeRec {
	return fakeRec{
		fields: map[string]any{
			"host":              "fw1.example.com",
			"app_name":          "sshd",
			"msg":               "Failed password for admin from 10.0.0.5",
			"status":            "new",
			"severity":          int64(4),
			"priority":          int64(0),
			"received_at":       time.Now().Add(-30 * time.Second),
			"structured.action": "blocked",
		},
		tags: map[int64]bool{7: true},
	}
}

func TestMatch(t *testing.T) {
	cases := []struct {
		name string
		cond string // JSON
		want bool
	}{
		{"empty matches all", `{}`, true},
		{"host contains", `{"field":"host","op":"contains","value":"FW1"}`, true},
		{"host eq full", `{"field":"host","op":"eq","value":"fw1.example.com"}`, true},
		{"host prefix miss", `{"field":"host","op":"prefix","value":"db"}`, false},
		{"severity lte", `{"field":"severity","op":"lte","value":4}`, true},
		{"severity lt miss", `{"field":"severity","op":"lt","value":4}`, false},
		{"null field ne", `{"field":"facility","op":"ne","value":3}`, true},
		{"null field eq", `{"field":"facility","op":"eq","value":3}`, false},
		{"text all words", `{"text":"failed admin"}`, true},
		{"text miss", `{"text":"succeeded admin"}`, false},
		{"structured", `{"field":"structured.action","op":"eq","value":"blocked"}`, true},
		{"tag", `{"tag_id":7}`, true},
		{"tag miss", `{"tag_id":8}`, false},
		{"window hit", `{"last_seconds":60}`, true},
		{"window miss", `{"last_seconds":10}`, false},
		{"and", `{"all":[{"field":"app_name","op":"eq","value":"sshd"},{"text":"failed"}]}`, true},
		{"or", `{"any":[{"field":"app_name","op":"eq","value":"nginx"},{"text":"failed"}]}`, true},
		{"not", `{"not":{"field":"status","op":"eq","value":"resolved"}}`, true},
		{"time gte", fmt.Sprintf(`{"field":"received_at","op":"gte","value":%q}`,
			time.Now().Add(-time.Minute).Format(time.RFC3339)), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var c Cond
			if err := json.Unmarshal([]byte(tc.cond), &c); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if err := c.Validate(); err != nil {
				t.Fatalf("validate: %v", err)
			}
			if got := c.Match(rec()); got != tc.want {
				t.Errorf("Match() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestValidateRejects(t *testing.T) {
	bad := []string{
		`{"field":"nope","op":"eq","value":"x"}`,
		`{"field":"host","op":"lt","value":"x"}`,
		`{"field":"severity","op":"contains","value":4}`,
		`{"field":"severity","op":"eq","value":"abc"}`,
		`{"field":"host","op":"eq","value":"x","text":"both set"}`,
		`{"all":[{"field":"bad","op":"eq","value":1}]}`,
	}
	for _, s := range bad {
		var c Cond
		if err := json.Unmarshal([]byte(s), &c); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if err := c.Validate(); err == nil {
			t.Errorf("Validate(%s) = nil, want error", s)
		}
	}
}

func TestCompileSQL(t *testing.T) {
	var c Cond
	src := `{"all":[
		{"field":"host","op":"contains","value":"fw_1"},
		{"any":[{"field":"severity","op":"lte","value":3},{"tag_id":7}]},
		{"not":{"text":"noise"}},
		{"field":"structured.action","op":"eq","value":"blocked"},
		{"last_seconds":3600}
	]}`
	if err := json.Unmarshal([]byte(src), &c); err != nil {
		t.Fatal(err)
	}
	var args []any
	arg := func(v any) string {
		args = append(args, v)
		return fmt.Sprintf("$%d", len(args))
	}
	sql, err := c.CompileSQL(arg)
	if err != nil {
		t.Fatal(err)
	}
	want := "(e.host ILIKE $1 AND (e.severity <= $2 OR EXISTS (SELECT 1 FROM entry_tags ct WHERE ct.entry_id = e.id AND ct.tag_id = $3)) AND NOT (e.msg_tsv @@ websearch_to_tsquery('simple', $4)) AND lower((e.structured->>$5)) = lower($6) AND e.received_at > now() - make_interval(secs => $7))"
	if sql != want {
		t.Errorf("sql:\n got %s\nwant %s", sql, want)
	}
	if args[0] != "%fw\\_1%" {
		t.Errorf("LIKE escape: got %q", args[0])
	}
	if len(args) != 7 {
		t.Errorf("args: got %d, want 7", len(args))
	}
}
