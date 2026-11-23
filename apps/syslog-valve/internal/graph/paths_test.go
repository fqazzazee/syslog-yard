package graph

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// diamond builds source -> layers of two filters, each fully connected to
// the next layer -> one forward: 2^layers source-to-sink paths.
func diamond(layers int) *Graph {
	g := &Graph{Nodes: []Node{
		{ID: "src", Type: TypeSource, Config: Config{Transport: "udp", Port: 514}},
		{ID: "out", Type: TypeForward, Config: Config{Transport: "udp", Host: "h", Port: 514}},
	}}
	prev := []string{"src"}
	for l := range layers {
		cur := []string{fmt.Sprintf("f%d-a", l), fmt.Sprintf("f%d-b", l)}
		for _, id := range cur {
			g.Nodes = append(g.Nodes, Node{ID: id, Type: TypeFilter, Config: Config{Program: "x"}})
			for _, p := range prev {
				g.Edges = append(g.Edges, Edge{From: p, To: id})
			}
		}
		prev = cur
	}
	for _, p := range prev {
		g.Edges = append(g.Edges, Edge{From: p, To: "out"})
	}
	return g
}

func validateWithin(t *testing.T, g *Graph, d time.Duration) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- g.Validate() }()
	select {
	case err := <-done:
		return err
	case <-time.After(d):
		t.Fatalf("Validate still running after %s", d)
		return nil
	}
}

func TestValidateRejectsPathExplosionQuickly(t *testing.T) {
	err := validateWithin(t, diamond(40), 3*time.Second)
	if err == nil || !strings.Contains(err.Error(), "log paths") {
		t.Fatalf("want a log path limit error, got %v", err)
	}
}

func TestValidateAcceptsModestDiamond(t *testing.T) {
	if err := validateWithin(t, diamond(6), 3*time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestValidateLogPathLimitBoundary(t *testing.T) {
	build := func(n int) *Graph {
		g := &Graph{Nodes: []Node{
			{ID: "src", Type: TypeSource, Config: Config{Transport: "udp", Port: 514}},
			{ID: "out", Type: TypeForward, Config: Config{Transport: "udp", Host: "h", Port: 514}},
		}}
		for range n {
			g.Edges = append(g.Edges, Edge{From: "src", To: "out"})
		}
		return g
	}
	if err := build(MaxLogPaths).Validate(); err != nil {
		t.Fatalf("at the limit: %v", err)
	}
	if err := build(MaxLogPaths + 1).Validate(); err == nil {
		t.Fatal("over the limit: want an error")
	}
}

// Disabled nodes generate no paths, so they don't count against the limit.
func TestValidateLogPathsIgnoreDisabled(t *testing.T) {
	g := diamond(20)
	for i := range g.Nodes {
		if strings.HasPrefix(g.Nodes[i].ID, "f10-") {
			g.Nodes[i].Disabled = true
		}
	}
	if err := validateWithin(t, g, 3*time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestValidateStillFindsCycleBehindSharedNode(t *testing.T) {
	g := diamond(3)
	g.Edges = append(g.Edges, Edge{From: "f2-a", To: "f0-a"})
	err := validateWithin(t, g, 3*time.Second)
	if err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("want a cycle error, got %v", err)
	}
}
