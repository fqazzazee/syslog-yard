package codegen

import (
	"strings"
	"testing"

	"github.com/syslog-yard/syslog-valve/internal/graph"
)

func testGraph() *graph.Graph {
	return &graph.Graph{
		Nodes: []graph.Node{
			{ID: "src-1", Type: graph.TypeSource, Name: "udp-in",
				Config: graph.Config{Transport: "udp", Port: 514}},
			{ID: "fwd-1", Type: graph.TypeForward, Name: "to-bucket",
				Config: graph.Config{Transport: "udp", Port: 514, Host: "bucket-syslog"}},
		},
		Edges: []graph.Edge{{From: "src-1", To: "fwd-1"}},
	}
}

func TestGenerate(t *testing.T) {
	conf, err := Generate(testGraph(), "4.8")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"@version: 4.8",
		`source s_src_1 {`,
		`network(ip("0.0.0.0") transport("udp") port(514));`,
		`destination d_fwd_1 {`,
		`network("bucket-syslog" port(514) transport("udp"));`,
		"log {\n    source(s_src_1);\n    destination(d_fwd_1);\n};",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("generated config missing %q:\n%s", want, conf)
		}
	}
}

func TestGenerateRejectsInvalid(t *testing.T) {
	g := testGraph()
	g.Nodes[1].Config.Host = ""
	if _, err := Generate(g, "4.8"); err == nil {
		t.Fatal("expected error for forward without host")
	}

	g = testGraph()
	g.Edges = []graph.Edge{{From: "fwd-1", To: "src-1"}}
	if _, err := Generate(g, "4.8"); err == nil {
		t.Fatal("expected error for reversed edge")
	}

	g = testGraph()
	g.Nodes[0].Config.Transport = "carrier-pigeon"
	if _, err := Generate(g, "4.8"); err == nil {
		t.Fatal("expected error for bad transport")
	}
}

func TestMinimalIsNonEmpty(t *testing.T) {
	if !strings.Contains(Minimal("4.8"), "@version: 4.8") {
		t.Fatal("minimal config malformed")
	}
}
