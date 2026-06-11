// Package rules holds the shared condition AST described in docs/PLAN.md §5:
// one grammar that powers buckets, rules, and live-tail subscriptions. A
// condition compiles two ways — to a SQL boolean expression over the entries
// table for queries and retroactive rule runs, and to an in-memory matcher
// for ingest-time rule evaluation and WebSocket fan-out.
package rules

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Cond is one JSON-serializable condition node. Exactly one of the groups
// below may be set; a zero Cond matches every entry.
type Cond struct {
	// Boolean combinators.
	All []Cond `json:"all,omitempty"`
	Any []Cond `json:"any,omitempty"`
	Not *Cond  `json:"not,omitempty"`

	// Field comparison leaf, e.g. {field:"severity",op:"lte",value:4} or
	// {field:"structured.action",op:"eq",value:"blocked"}.
	Field string `json:"field,omitempty"`
	Op    string `json:"op,omitempty"`
	Value any    `json:"value,omitempty"`

	// Free-text search over msg. SQL uses websearch syntax; the in-memory
	// matcher approximates it as "every word is a substring".
	Text string `json:"text,omitempty"`

	// Entry carries this tag.
	TagID int64 `json:"tag_id,omitempty"`

	// Entry was mapped to this MITRE ATT&CK technique at ingest (S8).
	Mitre string `json:"mitre,omitempty"`

	// Entry was received within the trailing window.
	LastSeconds int64 `json:"last_seconds,omitempty"`
}

// Record is the read view the in-memory matcher needs. *store.Entry
// implements it; the indirection keeps this package free of a store import.
type Record interface {
	// FieldValue returns a string, int64, or time.Time for a field name
	// (including "structured.<key>"), or ok=false when the entry has no
	// value for it.
	FieldValue(name string) (any, bool)
	HasTag(id int64) bool
}

type fieldKind int

const (
	kindStr fieldKind = iota
	kindNum
	kindTime
)

var fields = map[string]struct {
	col  string
	kind fieldKind
}{
	"host":         {"e.host", kindStr},
	"app_name":     {"e.app_name", kindStr},
	"device_class": {"e.device_class", kindStr},
	"msg":          {"e.msg", kindStr},
	"status":       {"e.status", kindStr},
	"severity":     {"e.severity", kindNum},
	"facility":     {"e.facility", kindNum},
	"priority":     {"e.priority", kindNum},
	"source_id":    {"e.source_id", kindNum},
	"received_at":  {"e.received_at", kindTime},
}

var strOps = map[string]bool{"eq": true, "ne": true, "contains": true, "prefix": true}
var ordOps = map[string]bool{"eq": true, "ne": true, "lt": true, "lte": true, "gt": true, "gte": true}

func (c Cond) kindCount() int {
	n := 0
	for _, set := range []bool{
		len(c.All) > 0, len(c.Any) > 0, c.Not != nil,
		c.Field != "", c.Text != "", c.TagID != 0, c.Mitre != "", c.LastSeconds != 0,
	} {
		if set {
			n++
		}
	}
	return n
}

// Validate checks the whole tree; CompileSQL and Match assume a valid tree.
func (c Cond) Validate() error {
	if c.kindCount() > 1 {
		return errors.New("condition node sets more than one of all/any/not/field/text/tag/window")
	}
	switch {
	case len(c.All) > 0 || len(c.Any) > 0:
		for _, sub := range append(c.All, c.Any...) {
			if err := sub.Validate(); err != nil {
				return err
			}
		}
	case c.Not != nil:
		return c.Not.Validate()
	case c.Field != "":
		return c.validateLeaf()
	case c.LastSeconds < 0:
		return errors.New("last_seconds must be positive")
	}
	return nil
}

func (c Cond) validateLeaf() error {
	kind := kindStr
	if !strings.HasPrefix(c.Field, "structured.") {
		f, ok := fields[c.Field]
		if !ok {
			return fmt.Errorf("unknown field %q", c.Field)
		}
		kind = f.kind
	}
	switch kind {
	case kindStr:
		if !strOps[c.Op] {
			return fmt.Errorf("op %q not valid for text field %q", c.Op, c.Field)
		}
		if _, err := strValue(c.Value); err != nil {
			return fmt.Errorf("field %q: %w", c.Field, err)
		}
	case kindNum:
		if !ordOps[c.Op] {
			return fmt.Errorf("op %q not valid for numeric field %q", c.Op, c.Field)
		}
		if _, err := numValue(c.Value); err != nil {
			return fmt.Errorf("field %q: %w", c.Field, err)
		}
	case kindTime:
		if !ordOps[c.Op] {
			return fmt.Errorf("op %q not valid for time field %q", c.Op, c.Field)
		}
		if _, err := timeValue(c.Value); err != nil {
			return fmt.Errorf("field %q: %w", c.Field, err)
		}
	}
	return nil
}

// CompileSQL renders the condition as a SQL boolean expression over the
// entries table (aliased "e"), registering bind values through arg, which
// must append the value and return its placeholder ("$n").
func (c Cond) CompileSQL(arg func(any) string) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	return c.compile(arg), nil
}

func (c Cond) compile(arg func(any) string) string {
	switch {
	case len(c.All) > 0:
		return c.compileJoin(c.All, " AND ", arg)
	case len(c.Any) > 0:
		return c.compileJoin(c.Any, " OR ", arg)
	case c.Not != nil:
		return "NOT (" + c.Not.compile(arg) + ")"
	case c.Field != "":
		return c.compileLeaf(arg)
	case c.Text != "":
		return "e.msg_tsv @@ websearch_to_tsquery('simple', " + arg(c.Text) + ")"
	case c.TagID != 0:
		return "EXISTS (SELECT 1 FROM entry_tags ct WHERE ct.entry_id = e.id AND ct.tag_id = " + arg(c.TagID) + ")"
	case c.Mitre != "":
		return arg(c.Mitre) + " = ANY(e.mitre)"
	case c.LastSeconds > 0:
		return "e.received_at > now() - make_interval(secs => " + arg(c.LastSeconds) + ")"
	default:
		return "TRUE"
	}
}

func (c Cond) compileJoin(subs []Cond, sep string, arg func(any) string) string {
	parts := make([]string, len(subs))
	for i, sub := range subs {
		parts[i] = sub.compile(arg)
	}
	return "(" + strings.Join(parts, sep) + ")"
}

func (c Cond) compileLeaf(arg func(any) string) string {
	col, kind := "", kindStr
	if key, ok := strings.CutPrefix(c.Field, "structured."); ok {
		col = "(e.structured->>" + arg(key) + ")"
	} else {
		f := fields[c.Field]
		col, kind = f.col, f.kind
	}

	switch kind {
	case kindStr:
		v, _ := strValue(c.Value)
		switch c.Op {
		case "eq":
			return "lower(" + col + ") = lower(" + arg(v) + ")"
		case "ne":
			return "lower(" + col + ") IS DISTINCT FROM lower(" + arg(v) + ")"
		case "contains":
			return col + " ILIKE " + arg("%"+escapeLike(v)+"%")
		case "prefix":
			return col + " ILIKE " + arg(escapeLike(v)+"%")
		}
	case kindNum:
		v, _ := numValue(c.Value)
		return col + " " + sqlOp(c.Op) + " " + arg(v)
	case kindTime:
		v, _ := timeValue(c.Value)
		return col + " " + sqlOp(c.Op) + " " + arg(v)
	}
	return "FALSE" // unreachable on a validated tree
}

func sqlOp(op string) string {
	switch op {
	case "eq":
		return "="
	case "ne":
		return "IS DISTINCT FROM"
	case "lt":
		return "<"
	case "lte":
		return "<="
	case "gt":
		return ">"
	default:
		return ">="
	}
}

func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}

// Match evaluates the condition against one entry in memory, mirroring the
// SQL semantics (NULL fields fail every op except ne).
func (c Cond) Match(rec Record) bool {
	switch {
	case len(c.All) > 0:
		for _, sub := range c.All {
			if !sub.Match(rec) {
				return false
			}
		}
		return true
	case len(c.Any) > 0:
		for _, sub := range c.Any {
			if sub.Match(rec) {
				return true
			}
		}
		return false
	case c.Not != nil:
		return !c.Not.Match(rec)
	case c.Field != "":
		return c.matchLeaf(rec)
	case c.Text != "":
		msg, _ := rec.FieldValue("msg")
		s, _ := msg.(string)
		return textMatch(s, c.Text)
	case c.TagID != 0:
		return rec.HasTag(c.TagID)
	case c.Mitre != "":
		v, ok := rec.FieldValue("mitre")
		ids, _ := v.([]string)
		if !ok {
			return false
		}
		for _, id := range ids {
			if id == c.Mitre {
				return true
			}
		}
		return false
	case c.LastSeconds > 0:
		v, ok := rec.FieldValue("received_at")
		t, isTime := v.(time.Time)
		return ok && isTime && time.Since(t) <= time.Duration(c.LastSeconds)*time.Second
	default:
		return true
	}
}

func (c Cond) matchLeaf(rec Record) bool {
	raw, ok := rec.FieldValue(c.Field)
	if !ok || raw == nil {
		return c.Op == "ne" // SQL: NULL IS DISTINCT FROM x
	}
	switch v := raw.(type) {
	case string:
		want, _ := strValue(c.Value)
		got, want := strings.ToLower(v), strings.ToLower(want)
		switch c.Op {
		case "eq":
			return got == want
		case "ne":
			return got != want
		case "contains":
			return strings.Contains(got, want)
		case "prefix":
			return strings.HasPrefix(got, want)
		}
	case int64:
		want, _ := numValue(c.Value)
		return ordCompare(float64(v), want, c.Op)
	case time.Time:
		want, _ := timeValue(c.Value)
		d := v.Compare(want)
		return ordCompare(float64(d), 0, c.Op)
	}
	return false
}

func ordCompare(got, want float64, op string) bool {
	switch op {
	case "eq":
		return got == want
	case "ne":
		return got != want
	case "lt":
		return got < want
	case "lte":
		return got <= want
	case "gt":
		return got > want
	default:
		return got >= want
	}
}

// textMatch approximates websearch_to_tsquery: every whitespace-separated
// token must appear in the message, case-insensitively.
func textMatch(msg, query string) bool {
	m := strings.ToLower(msg)
	for _, tok := range strings.Fields(strings.ToLower(query)) {
		if tok = strings.Trim(tok, `"`); tok == "" {
			continue
		}
		if !strings.Contains(m, tok) {
			return false
		}
	}
	return true
}

func strValue(v any) (string, error) {
	if s, ok := v.(string); ok {
		return s, nil
	}
	return "", fmt.Errorf("value %v must be a string", v)
}

func numValue(v any) (float64, error) {
	switch t := v.(type) {
	case float64:
		return t, nil
	case int:
		return float64(t), nil
	case int64:
		return float64(t), nil
	case int16:
		return float64(t), nil
	case string:
		return strconv.ParseFloat(t, 64)
	}
	return 0, fmt.Errorf("value %v must be a number", v)
}

func timeValue(v any) (time.Time, error) {
	s, ok := v.(string)
	if !ok {
		return time.Time{}, fmt.Errorf("value %v must be an RFC3339 string", v)
	}
	return time.Parse(time.RFC3339, s)
}
