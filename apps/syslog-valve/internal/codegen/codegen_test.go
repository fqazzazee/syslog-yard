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

func sevMax(n int) *int { return &n }

// source -> filter(sev<=3) -> match: forward, else: cache
func filteredGraph() *graph.Graph {
	return &graph.Graph{
		Nodes: []graph.Node{
			{ID: "src-1", Type: graph.TypeSource, Name: "udp-in",
				Config: graph.Config{Transport: "udp", Port: 514}},
			{ID: "f-1", Type: graph.TypeFilter, Name: "crit-high",
				Config: graph.Config{SeverityMax: sevMax(3)}},
			{ID: "fwd-1", Type: graph.TypeForward, Name: "to-bucket",
				Config: graph.Config{Transport: "udp", Port: 514, Host: "bucket-syslog"}},
			{ID: "c-1", Type: graph.TypeCache, Name: "noise",
				Config: graph.Config{Dir: "fw-noise", MaxSizeMB: 50, Rotate: 5, Compress: true}},
		},
		Edges: []graph.Edge{
			{From: "src-1", To: "f-1"},
			{From: "f-1", FromPort: graph.PortMatch, To: "fwd-1"},
			{From: "f-1", FromPort: graph.PortElse, To: "c-1"},
		},
	}
}

func TestGenerate(t *testing.T) {
	conf, err := Generate(testGraph(), "4.8", nil)
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

func TestGenerateFilterAndCache(t *testing.T) {
	conf, err := Generate(filteredGraph(), "4.8", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"filter f_f_1 {\n    level(emerg..err);\n};",
		"filter f_f_1_else {\n    not filter(f_f_1);\n};",
		`file("/data/cache/fw-noise/messages.log" create-dirs(yes));`,
		"log {\n    source(s_src_1);\n    filter(f_f_1);\n    destination(d_fwd_1);\n};",
		"log {\n    source(s_src_1);\n    filter(f_f_1_else);\n    destination(d_c_1);\n};",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("generated config missing %q:\n%s", want, conf)
		}
	}
}

func TestGenerateMultiConditionFilter(t *testing.T) {
	g := filteredGraph()
	g.Nodes[1].Config.Program = "fortigate"
	g.Nodes[1].Config.Match = `subtype="ips"`
	conf, err := Generate(g, "4.8", nil)
	if err != nil {
		t.Fatal(err)
	}
	want := `level(emerg..err) and program("fortigate") and message("subtype=\"ips\"")`
	if !strings.Contains(conf, want) {
		t.Errorf("missing combined filter %q:\n%s", want, conf)
	}
}

func TestCacheShares(t *testing.T) {
	g := filteredGraph()
	g.Nodes[3].Config.Location = "archive"

	if _, err := Generate(g, "4.8", nil); err == nil {
		t.Fatal("expected error for unconfigured share")
	}
	conf, err := Generate(g, "4.8", Shares{"archive": "/shares/archive"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(conf, `file("/shares/archive/fw-noise/messages.log"`) {
		t.Errorf("share path not used:\n%s", conf)
	}
}

func TestGenerateLogrotate(t *testing.T) {
	lr, err := GenerateLogrotate(filteredGraph(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"/data/cache/fw-noise/messages.log {",
		"copytruncate",
		"rotate 5",
		"size 50M",
		"compress",
	} {
		if !strings.Contains(lr, want) {
			t.Errorf("logrotate config missing %q:\n%s", want, lr)
		}
	}
	if empty, _ := GenerateLogrotate(testGraph(), nil); empty != "" {
		t.Errorf("graph without caches should yield empty logrotate config, got:\n%s", empty)
	}
}

func TestGenerateRejectsInvalid(t *testing.T) {
	g := testGraph()
	g.Nodes[1].Config.Host = ""
	if _, err := Generate(g, "4.8", nil); err == nil {
		t.Fatal("expected error for forward without host")
	}

	g = testGraph()
	g.Edges = []graph.Edge{{From: "fwd-1", To: "src-1"}}
	if _, err := Generate(g, "4.8", nil); err == nil {
		t.Fatal("expected error for reversed edge")
	}

	g = filteredGraph()
	g.Nodes[1].Config = graph.Config{}
	if _, err := Generate(g, "4.8", nil); err == nil {
		t.Fatal("expected error for filter without conditions")
	}
}

func TestMinimalIsNonEmpty(t *testing.T) {
	if !strings.Contains(Minimal("4.8"), "@version: 4.8") {
		t.Fatal("minimal config malformed")
	}
}

func TestGenerateTLS(t *testing.T) {
	g := &graph.Graph{
		Nodes: []graph.Node{
			{ID: "src-1", Type: graph.TypeSource, Name: "tls-in",
				Config: graph.Config{Transport: "tls", Port: 6514}},
			{ID: "fwd-1", Type: graph.TypeForward, Name: "to-siem",
				Config: graph.Config{Transport: "tls", Port: 6514, Host: "siem", TLSVerify: true}},
			{ID: "fwd-2", Type: graph.TypeForward, Name: "to-lab",
				Config: graph.Config{Transport: "tls", Port: 6514, Host: "lab"}},
		},
		Edges: []graph.Edge{
			{From: "src-1", To: "fwd-1"},
			{From: "src-1", To: "fwd-2"},
		},
	}
	conf, err := Generate(g, "4.8", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`transport("tls") port(6514) tls(key-file("/data/certs/valve.key") cert-file("/data/certs/valve.crt") peer-verify(optional-untrusted))`,
		`network("siem" port(6514) transport("tls") tls(peer-verify(required-trusted) ca-dir("/etc/ssl/certs")))`,
		`network("lab" port(6514) transport("tls") tls(peer-verify(optional-untrusted)))`,
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("generated config missing %q:\n%s", want, conf)
		}
	}
}

func TestGenerateTap(t *testing.T) {
	conf, err := Generate(testGraph(), "4.8", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`destination d_tap_src_1 {`,
		`unix-dgram("/data/syslog-ng/tap.sock" persist-name("tap_src_1") template("src_1\t${ISODATE}\t${HOST}\t${PROGRAM}\t${MSG}\n"));`,
		"log {\n    source(s_src_1);\n    destination(d_tap_src_1);\n};",
	} {
		if !strings.Contains(conf, want) {
			t.Errorf("generated config missing %q:\n%s", want, conf)
		}
	}
}
