package codegen

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// These tests run the generated configs through the real tools when they
// are installed (the container image has both); otherwise they skip.

func syslogNGVersion(t *testing.T, bin string) string {
	out, err := exec.Command(bin, "--version").CombinedOutput()
	if err != nil {
		t.Skipf("syslog-ng --version: %v", err)
	}
	m := regexp.MustCompile(`Config version: (\d+\.\d+)`).FindStringSubmatch(string(out))
	if m == nil {
		t.Skip("cannot determine syslog-ng config version")
	}
	return m[1]
}

func TestIntegrationSyslogNGSyntax(t *testing.T) {
	bin, err := exec.LookPath("syslog-ng")
	if err != nil {
		t.Skip("syslog-ng not installed")
	}
	ver := syslogNGVersion(t, bin)
	g := richGraph()
	hostile := "}; @include \"/etc\" `HOME` # { \\"
	for i := range g.Nodes {
		g.Nodes[i].Name = hostile
	}
	g.Nodes[1].Config.Match = "user `HOME` \"quoted\" \\d+"
	conf, err := Generate(g, ver, nil)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "syslog-ng.conf")
	if err := os.WriteFile(path, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(bin, "--syntax-only", "-f", path).CombinedOutput(); err != nil {
		t.Fatalf("syslog-ng rejected the generated config: %v\n%s\n%s", err, out, conf)
	}
	pre := filepath.Join(dir, "pre.conf")
	if out, err := exec.Command(bin, "--preprocess-into", pre, "-f", path).CombinedOutput(); err != nil {
		t.Fatalf("preprocess: %v\n%s", err, out)
	}
	data, err := os.ReadFile(pre)
	if err != nil {
		t.Fatal(err)
	}
	// Backtick references must survive as literal text, not be expanded to
	// the environment variable.
	if !strings.Contains(string(data), "`HOME`") {
		t.Errorf("backtick reference was expanded:\n%s", data)
	}
	if home := os.Getenv("HOME"); home != "" && strings.Contains(string(data), home) {
		t.Errorf("$HOME leaked into the config:\n%s", data)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "@include") && !strings.HasPrefix(strings.TrimSpace(line), "#") {
			t.Errorf("name escaped its comment: %q", line)
		}
	}
}

func TestIntegrationLogrotateParses(t *testing.T) {
	bin, err := exec.LookPath("logrotate")
	if err != nil {
		t.Skip("logrotate not installed")
	}
	dir := t.TempDir()
	share := filepath.Join(dir, "my archive") // a mount path with a space
	g := richGraph()
	g.Nodes[3].Name = "x\n    postrotate\n        touch " + filepath.Join(dir, "pwned") + "\n    endscript"
	g.Nodes[3].Config.Location = "arch"
	lr, err := GenerateLogrotate(g, Shares{"arch": share})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(lr, "postrotate") && !strings.Contains(lr, "# cache x     postrotate") {
		t.Fatalf("name escaped its comment:\n%s", lr)
	}
	conf := filepath.Join(dir, "logrotate.conf")
	if err := os.WriteFile(conf, []byte(lr), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "-d", "-s", filepath.Join(dir, "state"), conf).CombinedOutput()
	if err != nil {
		t.Fatalf("logrotate -d failed: %v\n%s\n%s", err, out, lr)
	}
	want := filepath.Join(share, "keep", "messages.log")
	if !strings.Contains(string(out), want) {
		t.Errorf("logrotate did not see %q:\n%s", want, out)
	}
	if strings.Contains(string(out), "postrotate") || strings.Contains(string(out), "running postrotate") {
		t.Errorf("logrotate parsed a postrotate script:\n%s", out)
	}
}
