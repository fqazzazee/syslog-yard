package graph

import (
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

// Limits on user-supplied text. Generous for real use, small enough that a
// graph can't balloon the generated config.
const (
	maxIDLen    = 64
	maxNameLen  = 200
	maxURLLen   = 2048
	maxMatchLen = 4096
	maxTextLen  = 512
)

var (
	idPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	// Cache subdirectories end up in syslog-ng file() paths and, quoted, in
	// logrotate.conf; keep them to a charset neither can misread.
	dirPattern = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)
	shareName  = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

func validID(id string) bool {
	return len(id) <= maxIDLen && idPattern.MatchString(id)
}

func validDir(dir string) bool {
	if len(dir) > maxTextLen || !dirPattern.MatchString(dir) || strings.HasPrefix(dir, "/") {
		return false
	}
	for _, seg := range strings.Split(dir, "/") {
		if seg == ".." {
			return false
		}
	}
	return true
}

// IsControl reports runes that must never appear in a graph string: C0
// controls (newline, carriage return, NUL, …), DEL, C1 controls, and the
// Unicode line/paragraph separators some tools treat as newlines.
func IsControl(r rune) bool {
	return r < 0x20 || (r >= 0x7f && r <= 0x9f) || r == ' ' || r == ' '
}

func hasControl(s string) bool {
	return strings.IndexFunc(s, IsControl) >= 0
}

type textField struct {
	name  string
	value *string
	max   int
}

// textFields lists every free-text string on a node, so validation and
// sanitizing can't miss one when a field is added.
func textFields(n *Node) []textField {
	c := &n.Config
	return []textField{
		{"type", &n.Type, maxTextLen},
		{"name", &n.Name, maxNameLen},
		{"transport", &c.Transport, maxTextLen},
		{"bind", &c.Bind, maxTextLen},
		{"host", &c.Host, maxTextLen},
		{"program", &c.Program, maxTextLen},
		{"match", &c.Match, maxMatchLen},
		{"technique", &c.Technique, maxTextLen},
		{"notifyKind", &c.NotifyKind, maxTextLen},
		{"url", &c.URL, maxURLLen},
		{"location", &c.Location, maxTextLen},
		{"dir", &c.Dir, maxTextLen},
	}
}

func checkText(n Node) error {
	for _, f := range textFields(&n) {
		if hasControl(*f.value) {
			return fmt.Errorf("node %q: %s must not contain control characters or line breaks", safeLabel(n), f.name)
		}
		if len(*f.value) > f.max {
			return fmt.Errorf("node %q: %s is longer than %d bytes", safeLabel(n), f.name, f.max)
		}
	}
	return nil
}

// safeLabel is label() for error messages about a node whose name is the
// problem: %q already escapes it, but keep the message short and plain.
func safeLabel(n Node) string {
	l := label(n)
	if len(l) > 64 {
		l = l[:64] + "…"
	}
	return strings.Map(func(r rune) rune {
		if IsControl(r) {
			return ' '
		}
		return r
	}, l)
}

// checkIdents rejects node IDs that compile to the same syslog-ng
// identifier ("a-b" and "a_b" both become a_b), or that collide with a name
// codegen derives for another node: d_tap_<source> and f_<filter>_else.
func (g *Graph) checkIdents() error {
	owner := map[string]string{}
	for _, n := range g.Nodes {
		id := Ident(n.ID)
		if prev, ok := owner[id]; ok {
			return fmt.Errorf("node ids %q and %q both compile to the identifier %q; rename one", prev, n.ID, id)
		}
		owner[id] = n.ID
	}
	for _, n := range g.Nodes {
		var derived, what string
		switch n.Type {
		case TypeSource:
			derived, what = "tap_"+Ident(n.ID), "live-tail destination"
		case TypeFilter:
			derived, what = Ident(n.ID)+"_else", "else-branch filter"
		default:
			continue
		}
		if other, ok := owner[derived]; ok {
			return fmt.Errorf("node id %q collides with the %s generated for node %q; rename it", other, what, n.ID)
		}
	}
	return nil
}

type listener struct {
	proto string
	port  int
	bind  string
	node  string
}

func sourceListeners(n Node) []listener {
	var protos []string
	switch n.Config.Transport {
	case "udp":
		protos = []string{"udp"}
	case "tcp", "tls":
		protos = []string{"tcp"}
	case "udp+tcp":
		protos = []string{"udp", "tcp"}
	}
	out := make([]listener, 0, len(protos))
	for _, p := range protos {
		out = append(out, listener{proto: p, port: n.Config.Port, bind: n.Config.Bind, node: label(n)})
	}
	return out
}

func wildcard(bind string) bool {
	switch strings.TrimSpace(bind) {
	case "", "0.0.0.0", "::", "[::]":
		return true
	}
	return false
}

func bindsOverlap(a, b string) bool {
	return wildcard(a) || wildcard(b) || strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
}

// checkListeners rejects two enabled sources listening on the same
// transport and port: --syntax-only accepts that, but syslog-ng then fails
// to bind at reload (and refuses to start cold).
func (g *Graph) checkListeners() error {
	var seen []listener
	for _, n := range g.Nodes {
		if n.Type != TypeSource || n.Disabled {
			continue
		}
		for _, l := range sourceListeners(n) {
			for _, o := range seen {
				if o.proto == l.proto && o.port == l.port && bindsOverlap(o.bind, l.bind) {
					return fmt.Errorf("sources %q and %q both listen on %s/%d", o.node, l.node, l.proto, l.port)
				}
			}
			seen = append(seen, l)
		}
	}
	return nil
}

// CheckReservedPort rejects an enabled source listening on a port the
// valve process itself already holds (its HTTP UI, for instance).
func (g *Graph) CheckReservedPort(proto string, port int, what string) error {
	if port <= 0 {
		return nil
	}
	for _, n := range g.Nodes {
		if n.Type != TypeSource || n.Disabled {
			continue
		}
		for _, l := range sourceListeners(n) {
			if l.proto == proto && l.port == port {
				return fmt.Errorf("source %q: %s/%d is already used by %s", l.node, proto, port, what)
			}
		}
	}
	return nil
}

// CheckNotifyURL accepts only absolute http(s) URLs with a host.
func CheckNotifyURL(raw string) error {
	if len(raw) > maxURLLen || hasControl(raw) {
		return fmt.Errorf("notify URL is too long or contains control characters")
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("notify URL is not valid")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("notify URL must be http:// or https://")
	}
	if u.Hostname() == "" {
		return fmt.Errorf("notify URL needs a host")
	}
	return nil
}

// Sanitize replaces control characters in every free-text field with a
// space and reports whether anything changed. It is for loading graphs
// saved by older versions, which validated less; new input is rejected by
// Validate instead.
func (g *Graph) Sanitize() bool {
	changed := false
	clean := func(r rune) rune {
		if IsControl(r) {
			return ' '
		}
		return r
	}
	for i := range g.Nodes {
		for _, f := range textFields(&g.Nodes[i]) {
			if hasControl(*f.value) {
				*f.value = strings.Map(clean, *f.value)
				changed = true
			}
		}
	}
	return changed
}

// Load parses a previously stored graph (the applied version, a history
// entry): control characters are sanitized away rather than rejected so an
// old graph keeps loading, then the result must pass Validate. sanitized
// reports whether the stored data had to be changed.
func Load(data []byte) (g *Graph, sanitized bool, err error) {
	g = &Graph{}
	if err := json.Unmarshal(data, g); err != nil {
		return nil, false, fmt.Errorf("invalid graph JSON: %w", err)
	}
	sanitized = g.Sanitize()
	if err := g.Validate(); err != nil {
		return nil, sanitized, err
	}
	return g, sanitized, nil
}
