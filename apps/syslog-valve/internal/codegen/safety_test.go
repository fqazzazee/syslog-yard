package codegen

import (
	"strings"
	"testing"

	"github.com/syslog-yard/syslog-valve/internal/graph"
)

// richGraph exercises every node type so the injection tests cover every
// place codegen writes a user value.
func richGraph() *graph.Graph {
	return &graph.Graph{
		Nodes: []graph.Node{
			{ID: "src-1", Type: graph.TypeSource, Name: "in", Config: graph.Config{Transport: "udp+tcp", Port: 6514}},
			{ID: "f-1", Type: graph.TypeFilter, Name: "filter", Config: graph.Config{Program: "sshd", Match: "fail"}},
			{ID: "fwd-1", Type: graph.TypeForward, Name: "fwd", Config: graph.Config{Transport: "tcp", Port: 514, Host: "bucket"}},
			{ID: "c-1", Type: graph.TypeCache, Name: "cache", Config: graph.Config{Dir: "keep", Rotate: 3}},
			{ID: "n-1", Type: graph.TypeNotify, Name: "notify", Config: graph.Config{NotifyKind: "webhook", URL: "http://sink:9000/x"}},
		},
		Edges: []graph.Edge{
			{From: "src-1", To: "f-1"},
			{From: "f-1", FromPort: graph.PortMatch, To: "fwd-1"},
			{From: "f-1", FromPort: graph.PortElse, To: "c-1"},
			{From: "src-1", To: "n-1"},
		},
	}
}

const injected = "x\n};\ndestination d_pwn { program(\"/bin/sh -c id\"); };\nlog { source(s_src_1); destination(d_pwn); };\n#"

func TestHostileNamesRejectedBeforeCodegen(t *testing.T) {
	for i := range richGraph().Nodes {
		g := richGraph()
		g.Nodes[i].Name = injected
		if _, err := Generate(g, "4.8", nil); err == nil {
			t.Errorf("node %d: Generate accepted a name with newlines", i)
		}
	}
}

func TestHostileDirRejected(t *testing.T) {
	g := richGraph()
	g.Nodes[3].Config.Dir = "x\n    postrotate\n        id > /tmp/pwned\n    endscript\n"
	if _, err := Generate(g, "4.8", nil); err == nil {
		t.Fatal("Generate accepted a dir with newlines")
	}
	// GenerateLogrotate is also called on its own; it must refuse the path
	// even without graph validation in front of it.
	if lr, err := GenerateLogrotate(g, nil); err == nil {
		t.Fatalf("GenerateLogrotate accepted a hostile dir:\n%s", lr)
	}
	g.Nodes[3].Config.Dir = `a" {`
	if _, err := GenerateLogrotate(g, nil); err == nil {
		t.Fatal("GenerateLogrotate accepted a quote in the path")
	}
}

func TestCommentStripsLineBreaks(t *testing.T) {
	for _, in := range []string{"a\nb", "a\rb", "a b", "a b", "a\x00b", "a\u0085b", "a\x7fb"} {
		if got := comment(in); got != "a b" {
			t.Errorf("comment(%q) = %q", in, got)
		}
	}
	if got := comment("`HOME`"); got != "``HOME``" {
		t.Errorf("backticks not escaped: %q", got)
	}
}

func TestQuoteEscapesBackticks(t *testing.T) {
	if got := q("a`HOME`b\"c\\"); got != "\"a``HOME``b\\\"c\\\\\"" {
		t.Errorf("q = %s", got)
	}
}

func TestHostileButValidNamesStayInComments(t *testing.T) {
	g := richGraph()
	for i := range g.Nodes {
		g.Nodes[i].Name = "}; @include \"/etc\" `HOME` # {"
	}
	conf, err := Generate(g, "4.8", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(conf, "\n") {
		if strings.Contains(line, "@include") && !strings.HasPrefix(line, "# ") {
			t.Errorf("name escaped its comment: %q", line)
		}
	}
	if strings.Contains(conf, " `HOME` ") {
		t.Errorf("unescaped backtick reference in output:\n%s", conf)
	}
}

func lines(s string) int { return strings.Count(s, "\n") }

// FuzzGenerate feeds arbitrary text into every free-text field. Whatever
// validation lets through, the output must have exactly the line structure
// of the same graph with plain values: no field can add a line.
func FuzzGenerate(f *testing.F) {
	for _, s := range []string{"x", injected, "a\rb", "a b", "`HOME`", "\"; }", "\\", "a\x00"} {
		f.Add(s, s, s, s)
	}
	baseConf, err := Generate(richGraph(), "4.8", nil)
	if err != nil {
		f.Fatal(err)
	}
	baseLR, err := GenerateLogrotate(richGraph(), nil)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, name, host, match, dir string) {
		g := richGraph()
		for i := range g.Nodes {
			g.Nodes[i].Name = name
		}
		g.Nodes[1].Config.Program = host
		g.Nodes[1].Config.Match = match
		g.Nodes[2].Config.Host = host
		g.Nodes[3].Config.Dir = dir
		if conf, err := Generate(g, "4.8", nil); err == nil {
			if lines(conf) != lines(baseConf) {
				t.Fatalf("config gained lines:\n%s", conf)
			}
		}
		// GenerateLogrotate does not validate the graph itself.
		if lr, err := GenerateLogrotate(g, nil); err == nil {
			if lines(lr) != lines(baseLR) {
				t.Fatalf("logrotate config gained lines:\n%s", lr)
			}
			for _, line := range strings.Split(lr, "\n") {
				if strings.HasPrefix(line, "#") {
					continue
				}
				if strings.Contains(line, "{") && !strings.HasSuffix(line, `/messages.log" {`) {
					t.Fatalf("logrotate config gained a block:\n%s", lr)
				}
			}
		}
	})
}
