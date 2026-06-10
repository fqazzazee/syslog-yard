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
	TypeForward = "forward"
)

// Config carries the union of per-type settings; codegen reads only the
// fields relevant to the node's type.
type Config struct {
	Transport string `json:"transport,omitempty"` // udp | tcp
	Port      int    `json:"port,omitempty"`
	Bind      string `json:"bind,omitempty"` // source: listen address
	Host      string `json:"host,omitempty"` // forward: destination host
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
	From string `json:"from"`
	To   string `json:"to"`
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

func (g *Graph) node(id string) *Node {
	for i := range g.Nodes {
		if g.Nodes[i].ID == id {
			return &g.Nodes[i]
		}
	}
	return nil
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

		switch n.Type {
		case TypeSource:
			if err := checkTransport(n); err != nil {
				return err
			}
			if err := checkPort(n); err != nil {
				return err
			}
		case TypeForward:
			if err := checkTransport(n); err != nil {
				return err
			}
			if err := checkPort(n); err != nil {
				return err
			}
			if strings.TrimSpace(n.Config.Host) == "" {
				return fmt.Errorf("node %q: forward needs a destination host", label(n))
			}
		default:
			return fmt.Errorf("node %q: unknown type %q", label(n), n.Type)
		}
	}
	for _, e := range g.Edges {
		from, to := g.node(e.From), g.node(e.To)
		if from == nil || to == nil {
			return fmt.Errorf("edge %s -> %s references a missing node", e.From, e.To)
		}
		if from.Type != TypeSource {
			return fmt.Errorf("edge from %q: only source nodes have outputs", label(*from))
		}
		if to.Type != TypeForward {
			return fmt.Errorf("edge to %q: only forward nodes have inputs", label(*to))
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
