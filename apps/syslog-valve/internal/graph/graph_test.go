package graph

import (
	"encoding/json"
	"strings"
	"testing"
)

func base() *Graph {
	return &Graph{
		Nodes: []Node{
			{ID: "source-1", Type: TypeSource, Name: "in", Config: Config{Transport: "udp", Port: 514}},
			{ID: "forward-1", Type: TypeForward, Name: "out", Config: Config{Transport: "tcp", Port: 514, Host: "bucket"}},
			{ID: "cache-1", Type: TypeCache, Name: "keep", Config: Config{Dir: "fw/noise"}},
			{ID: "notify-1", Type: TypeNotify, Name: "page", Config: Config{NotifyKind: "slack", URL: "https://hooks.example/x"}},
			{ID: "filter-1", Type: TypeFilter, Name: "f", Config: Config{Program: "sshd"}},
		},
		Edges: []Edge{
			{From: "source-1", To: "filter-1"},
			{From: "filter-1", FromPort: PortMatch, To: "forward-1"},
			{From: "filter-1", FromPort: PortElse, To: "cache-1"},
			{From: "source-1", To: "notify-1"},
		},
	}
}

func TestValidateBase(t *testing.T) {
	if err := base().Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejects(t *testing.T) {
	cases := map[string]func(g *Graph){
		"newline in name":         func(g *Graph) { g.Nodes[0].Name = "x\n};\ndestination d { program(\"id\"); };" },
		"CR in name":              func(g *Graph) { g.Nodes[1].Name = "x\rboom" },
		"NUL in host":             func(g *Graph) { g.Nodes[1].Config.Host = "bucket\x00" },
		"DEL in program":          func(g *Graph) { g.Nodes[4].Config.Program = "ssh\x7f" },
		"C1 in match":             func(g *Graph) { g.Nodes[4].Config.Match = "a\u0085b" },
		"U+2028 in name":          func(g *Graph) { g.Nodes[2].Name = "a b" },
		"U+2029 in bind":          func(g *Graph) { g.Nodes[0].Config.Bind = "0.0.0.0 " },
		"newline in url":          func(g *Graph) { g.Nodes[3].Config.URL = "https://x/\nfoo" },
		"tab in location":         func(g *Graph) { g.Nodes[2].Config.Location = "a\tb" },
		"newline in dir":          func(g *Graph) { g.Nodes[2].Config.Dir = "x\n    postrotate\n id\n    endscript" },
		"space in dir":            func(g *Graph) { g.Nodes[2].Config.Dir = "a b" },
		"quote in dir":            func(g *Graph) { g.Nodes[2].Config.Dir = `a"b` },
		"brace in dir":            func(g *Graph) { g.Nodes[2].Config.Dir = "a}b" },
		"dotdot in dir":           func(g *Graph) { g.Nodes[2].Config.Dir = "a/../../etc" },
		"absolute dir":            func(g *Graph) { g.Nodes[2].Config.Dir = "/etc" },
		"bad share name":          func(g *Graph) { g.Nodes[2].Config.Location = "../x" },
		"empty id":                func(g *Graph) { g.Nodes[0].ID = "" },
		"id with space":           func(g *Graph) { g.Nodes[0].ID = "a b" },
		"id with brace":           func(g *Graph) { g.Nodes[0].ID = "a{}" },
		"id too long":             func(g *Graph) { g.Nodes[0].ID = strings.Repeat("a", 65) },
		"name too long":           func(g *Graph) { g.Nodes[0].Name = strings.Repeat("a", 201) },
		"ftp notify url":          func(g *Graph) { g.Nodes[3].Config.URL = "file:///etc/passwd" },
		"notify url without host": func(g *Graph) { g.Nodes[3].Config.URL = "http:///x" },
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			g := base()
			mut(g)
			if err := g.Validate(); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestValidateAcceptsOrdinaryDirs(t *testing.T) {
	for _, d := range []string{"fw", "fw/noise", "a.b_c-d", "x/y/z", "..hidden", "a..b"} {
		g := base()
		g.Nodes[2].Config.Dir = d
		if err := g.Validate(); err != nil {
			t.Errorf("dir %q rejected: %v", d, err)
		}
	}
}

func TestValidateIdentCollisions(t *testing.T) {
	t.Run("dash vs underscore", func(t *testing.T) {
		g := base()
		g.Nodes = append(g.Nodes, Node{ID: "source_1", Type: TypeSource, Config: Config{Transport: "udp", Port: 515}})
		if err := g.Validate(); err == nil || !strings.Contains(err.Error(), "identifier") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("case", func(t *testing.T) {
		g := base()
		g.Nodes = append(g.Nodes, Node{ID: "Source-1", Type: TypeSource, Config: Config{Transport: "udp", Port: 515}})
		if err := g.Validate(); err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("tap destination", func(t *testing.T) {
		g := base()
		g.Nodes = append(g.Nodes, Node{ID: "tap_source-1", Type: TypeForward, Config: Config{Transport: "udp", Port: 514, Host: "h"}})
		if err := g.Validate(); err == nil || !strings.Contains(err.Error(), "live-tail") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("else filter", func(t *testing.T) {
		g := base()
		g.Nodes = append(g.Nodes, Node{ID: "filter-1_else", Type: TypeFilter, Config: Config{Program: "x"}})
		if err := g.Validate(); err == nil || !strings.Contains(err.Error(), "else-branch") {
			t.Fatalf("err = %v", err)
		}
	})
}

func TestValidateDuplicateListeners(t *testing.T) {
	add := func(g *Graph, id, tr string, port int, bind string, disabled bool) {
		g.Nodes = append(g.Nodes, Node{ID: id, Type: TypeSource, Disabled: disabled, Config: Config{Transport: tr, Port: port, Bind: bind}})
	}
	cases := []struct {
		name string
		mut  func(g *Graph)
		ok   bool
	}{
		{"same udp port", func(g *Graph) { add(g, "s2", "udp", 514, "", false) }, false},
		{"udp+tcp overlaps udp", func(g *Graph) { add(g, "s2", "udp+tcp", 514, "", false) }, false},
		{"tls vs tcp", func(g *Graph) {
			add(g, "s2", "tcp", 6514, "", false)
			add(g, "s3", "tls", 6514, "", false)
		}, false},
		{"wildcard vs specific", func(g *Graph) { add(g, "s2", "udp", 514, "10.0.0.1", false) }, false},
		{"different proto", func(g *Graph) { add(g, "s2", "tcp", 514, "", false) }, true},
		{"different port", func(g *Graph) { add(g, "s2", "udp", 515, "", false) }, true},
		{"distinct binds", func(g *Graph) {
			g.Nodes[0].Config.Bind = "10.0.0.1"
			add(g, "s2", "udp", 514, "10.0.0.2", false)
		}, true},
		{"disabled duplicate", func(g *Graph) { add(g, "s2", "udp", 514, "", true) }, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := base()
			c.mut(g)
			err := g.Validate()
			if c.ok && err != nil {
				t.Fatalf("rejected: %v", err)
			}
			if !c.ok && err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestCheckReservedPort(t *testing.T) {
	g := base()
	g.Nodes[0].Config.Transport = "udp+tcp"
	g.Nodes[0].Config.Port = 8081
	if err := g.CheckReservedPort("tcp", 8081, "the valve UI"); err == nil {
		t.Fatal("accepted source on the UI port")
	}
	if err := g.CheckReservedPort("tcp", 8082, "the valve UI"); err != nil {
		t.Fatal(err)
	}
	g.Nodes[0].Disabled = true
	if err := g.CheckReservedPort("tcp", 8081, "the valve UI"); err != nil {
		t.Fatal(err)
	}
}

func TestLoadSanitizesOldGraphs(t *testing.T) {
	g := base()
	g.Nodes[0].Name = "evil\n@include \"/etc\""
	g.Nodes[4].Config.Program = "ssh\r"
	data, _ := json.Marshal(g)
	if _, err := Parse(data); err == nil {
		t.Fatal("Parse accepted control characters")
	}
	got, sanitized, err := Load(data)
	if err != nil {
		t.Fatal(err)
	}
	if !sanitized {
		t.Fatal("sanitized = false")
	}
	if got.Nodes[0].Name != `evil @include "/etc"` || got.Nodes[4].Config.Program != "ssh " {
		t.Fatalf("not sanitized: %q %q", got.Nodes[0].Name, got.Nodes[4].Config.Program)
	}
	// A clean graph loads unchanged.
	data, _ = json.Marshal(base())
	if _, sanitized, err := Load(data); err != nil || sanitized {
		t.Fatalf("clean graph: sanitized=%v err=%v", sanitized, err)
	}
}
