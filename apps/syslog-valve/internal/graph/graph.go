// Package graph defines the flow graph the UI edits: nodes with typed
// configs joined by edges. The graph is the single source of truth; the
// syslog-ng config is always regenerated from it, never edited directly.
package graph

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

const (
	TypeSource  = "source"
	TypeFilter  = "filter"
	TypeForward = "forward"
	TypeCache   = "cache"
)

// Filter output ports: edges leaving a filter carry the branch they take.
const (
	PortMatch = "match"
	PortElse  = "else"
)

// Severity indices follow syslog: 0=emerg .. 7=debug.
var SeverityNames = []string{"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"}

// Config carries the union of per-type settings; codegen reads only the
// fields relevant to the node's type.
type Config struct {
	Transport string `json:"transport,omitempty"` // source/forward: udp | tcp
	Port      int    `json:"port,omitempty"`
	Bind      string `json:"bind,omitempty"` // source: listen address
	Host      string `json:"host,omitempty"` // forward: destination host

	// filter: conditions are ANDed; at least one must be set
	SeverityMax *int   `json:"severityMax,omitempty"` // pass if severity <= this
	Program     string `json:"program,omitempty"`
	Match       string `json:"match,omitempty"` // regex on the message text

	// cache: file destination with logrotate retention
	Location   string `json:"location,omitempty"` // "" = local /data, else share name
	Dir        string `json:"dir,omitempty"`      // subdirectory (defaults to node ident)
	MaxSizeMB  int    `json:"maxSizeMB,omitempty"`
	MaxAgeDays int    `json:"maxAgeDays,omitempty"`
	Rotate     int    `json:"rotate,omitempty"` // rotations kept, default 7
	Compress   bool   `json:"compress,omitempty"`
}

type Node struct {
	ID     string  `json:"id"`
	Type   string  `json:"type"`
	Name   string  `json:"name"`
	X      float64 `json:"x"`
	Y      float64 `json:"y"`
	Config Config  `json:"config"`
}

type Edge struct {
	From     string `json:"from"`
	FromPort string `json:"fromPort,omitempty"` // only meaningful from filters
	To       string `json:"to"`
}

type Graph struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

func Parse(data []byte) (*Graph, error) {
	var g Graph
	if err := json.Unmarshal(data, &g); err != nil {
		return nil, fmt.Errorf("invalid graph JSON: %w", err)
	}
	if err := g.Validate(); err != nil {
		return nil, err
	}
	return &g, nil
}

func (g *Graph) Node(id string) *Node {
	for i := range g.Nodes {
		if g.Nodes[i].ID == id {
			return &g.Nodes[i]
		}
	}
	return nil
}

func (g *Graph) EdgesFrom(id string) []Edge {
	var out []Edge
	for _, e := range g.Edges {
		if e.From == id {
			out = append(out, e)
		}
	}
	return out
}

func (g *Graph) Validate() error {
	seen := map[string]bool{}
	for _, n := range g.Nodes {
		if n.ID == "" {
			return fmt.Errorf("node with empty id")
		}
		if seen[n.ID] {
			return fmt.Errorf("duplicate node id %q", n.ID)
		}
		seen[n.ID] = true
		if err := validateNode(n); err != nil {
			return err
		}
	}
	for _, e := range g.Edges {
		if err := g.validateEdge(e); err != nil {
			return err
		}
	}
	return g.checkCycles()
}

func validateNode(n Node) error {
	switch n.Type {
	case TypeSource:
		if err := checkTransport(n); err != nil {
			return err
		}
		return checkPort(n)
	case TypeForward:
		if err := checkTransport(n); err != nil {
			return err
		}
		if strings.TrimSpace(n.Config.Host) == "" {
			return fmt.Errorf("node %q: forward needs a destination host", label(n))
		}
		return checkPort(n)
	case TypeFilter:
		c := n.Config
		if c.SeverityMax == nil && strings.TrimSpace(c.Program) == "" && strings.TrimSpace(c.Match) == "" {
			return fmt.Errorf("node %q: filter needs at least one condition", label(n))
		}
		if c.SeverityMax != nil && (*c.SeverityMax < 0 || *c.SeverityMax > 7) {
			return fmt.Errorf("node %q: severityMax must be 0..7", label(n))
		}
		if c.Match != "" {
			if _, err := regexp.Compile(c.Match); err != nil {
				return fmt.Errorf("node %q: bad match regex: %v", label(n), err)
			}
		}
		return nil
	case TypeCache:
		c := n.Config
		if strings.Contains(c.Dir, "..") || strings.HasPrefix(c.Dir, "/") {
			return fmt.Errorf("node %q: cache dir must be a relative subdirectory", label(n))
		}
		if c.Rotate < 0 || c.MaxSizeMB < 0 || c.MaxAgeDays < 0 {
			return fmt.Errorf("node %q: retention values must be >= 0", label(n))
		}
		return nil
	default:
		return fmt.Errorf("node %q: unknown type %q", label(n), n.Type)
	}
}

func (g *Graph) validateEdge(e Edge) error {
	from, to := g.Node(e.From), g.Node(e.To)
	if from == nil || to == nil {
		return fmt.Errorf("edge %s -> %s references a missing node", e.From, e.To)
	}
	switch from.Type {
	case TypeSource:
		if e.FromPort != "" {
			return fmt.Errorf("edge from %q: sources have a single output", label(*from))
		}
	case TypeFilter:
		if e.FromPort != "" && e.FromPort != PortMatch && e.FromPort != PortElse {
			return fmt.Errorf("edge from %q: port must be %q or %q", label(*from), PortMatch, PortElse)
		}
	default:
		return fmt.Errorf("edge from %q: %s nodes have no outputs", label(*from), from.Type)
	}
	if to.Type != TypeFilter && to.Type != TypeForward && to.Type != TypeCache {
		return fmt.Errorf("edge to %q: %s nodes have no inputs", label(*to), to.Type)
	}
	return nil
}

func (g *Graph) checkCycles() error {
	var visit func(id string, stack map[string]bool) error
	visit = func(id string, stack map[string]bool) error {
		if stack[id] {
			return fmt.Errorf("graph has a cycle through %q", id)
		}
		stack[id] = true
		defer delete(stack, id)
		for _, e := range g.EdgesFrom(id) {
			if err := visit(e.To, stack); err != nil {
				return err
			}
		}
		return nil
	}
	for _, n := range g.Nodes {
		if n.Type == TypeSource {
			if err := visit(n.ID, map[string]bool{}); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkTransport(n Node) error {
	switch n.Config.Transport {
	case "udp", "tcp":
		return nil
	default:
		return fmt.Errorf("node %q: transport must be udp or tcp, got %q", label(n), n.Config.Transport)
	}
}

func checkPort(n Node) error {
	if n.Config.Port < 1 || n.Config.Port > 65535 {
		return fmt.Errorf("node %q: port %d out of range", label(n), n.Config.Port)
	}
	return nil
}

func label(n Node) string {
	if n.Name != "" {
		return n.Name
	}
	return n.ID
}

var unsafeIdent = regexp.MustCompile(`[^a-z0-9_]+`)

// Ident turns a node ID into a safe syslog-ng identifier fragment.
func Ident(id string) string {
	return unsafeIdent.ReplaceAllString(strings.ToLower(id), "_")
}
