package codegen

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/syslog-yard/syslog-valve/internal/graph"
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

// TestIntegrationSourceAutoDetect runs a generated source → forward flow
// through the real syslog-ng and checks what reaches the next hop: RFC 5424
// keeps its host, app and structured data; RFC 3164 and bare "<PRI>k=v"
// lines (FortiGate) pass as before.
func TestIntegrationSourceAutoDetect(t *testing.T) {
	bin, err := exec.LookPath("syslog-ng")
	if err != nil {
		t.Skip("syslog-ng not installed")
	}
	ver := syslogNGVersion(t, bin)

	sink, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer sink.Close()
	free, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	inPort := free.Addr().(*net.TCPAddr).Port
	free.Close()

	g := &graph.Graph{
		Nodes: []graph.Node{
			{ID: "src-1", Type: graph.TypeSource, Name: "in",
				Config: graph.Config{Transport: "tcp", Port: inPort, Bind: "127.0.0.1"}},
			{ID: "fwd-1", Type: graph.TypeForward, Name: "next",
				Config: graph.Config{Transport: "tcp", Port: sink.Addr().(*net.TCPAddr).Port, Host: "127.0.0.1"}},
		},
		Edges: []graph.Edge{{From: "src-1", To: "fwd-1"}},
	}
	conf, err := Generate(g, ver, nil)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	conf = strings.ReplaceAll(conf, TapSocket, filepath.Join(dir, "tap.sock"))
	path := filepath.Join(dir, "syslog-ng.conf")
	if err := os.WriteFile(path, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-F", "--no-caps", "-f", path,
		"--persist-file", filepath.Join(dir, "persist"),
		"--pidfile", filepath.Join(dir, "pid"),
		"--control", filepath.Join(dir, "ctl"))
	var stderr strings.Builder
	cmd.Stdout, cmd.Stderr = &stderr, &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()

	var in net.Conn
	for deadline := time.Now().Add(5 * time.Second); ; {
		in, err = net.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(inPort)))
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("syslog-ng never listened: %v\n%s", err, stderr.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	// Real hose preset lines: juniper-srx, linux-host, fortinet-fortigate.
	lines := []string{
		`<150>1 2026-11-05T10:06:28.699Z juniper-45 RT_FLOW - RT_FLOW_SESSION_CLOSE [junos@2636.1.1.1.2.129 reason="idle Timeout" source-address="172.17.165.245"] session closed`,
		`<37>Nov  5 10:06:28 linux-45 sudo[15987]: jsmith : TTY=pts/3 ; USER=root`,
		`<188>date=2026-11-05 time=10:06:28 devname="fw-01" devid="FGT60FTK2009012345" logid="0000000013" type="traffic"`,
	}
	for _, l := range lines {
		fmt.Fprintln(in, l)
	}
	in.Close()

	sink.(*net.TCPListener).SetDeadline(time.Now().Add(5 * time.Second))
	c, err := sink.Accept()
	if err != nil {
		t.Fatalf("nothing forwarded: %v\n%s", err, stderr.String())
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	sc := bufio.NewScanner(c)
	var got []string
	for len(got) < len(lines) && sc.Scan() {
		got = append(got, sc.Text())
	}
	if len(got) != len(lines) {
		t.Fatalf("forwarded %d of %d lines: %q\n%s", len(got), len(lines), got, stderr.String())
	}
	for i, want := range []string{
		` juniper-45 RT_FLOW: [junos@2636.1.1.1.2.129 reason="idle Timeout" source-address="172.17.165.245"] session closed`,
		` linux-45 sudo[15987]: jsmith : TTY=pts/3 ; USER=root`,
		`devname="fw-01" devid="FGT60FTK2009012345"`,
	} {
		if !strings.Contains(got[i], want) {
			t.Errorf("line %d: got %q, want it to contain %q", i, got[i], want)
		}
	}
	if !strings.HasPrefix(got[0], "<150>") || !strings.HasPrefix(got[2], "<188>") {
		t.Errorf("priority not kept: %q", got)
	}
}
