package supervisor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"testing"
)

// TestIntegrationReloadRejected runs the real syslog-ng (when installed):
// a config with two sources on one port passes --syntax-only but fails at
// reload, and Apply must report that and restore current.conf.
func TestIntegrationReloadRejected(t *testing.T) {
	bin, err := exec.LookPath("syslog-ng")
	if err != nil {
		t.Skip("syslog-ng not installed")
	}
	out, _ := exec.Command(bin, "--version").CombinedOutput()
	m := regexp.MustCompile(`Config version: (\d+\.\d+)`).FindSubmatch(out)
	if m == nil {
		t.Skip("cannot determine syslog-ng config version")
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()

	head := fmt.Sprintf("@version: %s\noptions { use-dns(no); };\n", m[1])
	src := func(name string) string {
		return fmt.Sprintf("source %s { network(ip(\"127.0.0.1\") transport(\"tcp\") port(%d)); };\nlog { source(%s); };\n", name, port, name)
	}
	good := head + src("s_a")
	clash := good + src("s_b")

	s := New(bin, t.TempDir())
	if err := s.Start(context.Background(), head); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Shutdown)
	waitFor(t, "syslog-ng startup", func() bool { return logHas(s, "starting up") })
	if !s.Status().Running {
		t.Skipf("syslog-ng did not stay up here (non-root?): %v", s.Status().Log)
	}

	if err := s.Apply(good, []byte(`{"v":1}`)); err != nil {
		t.Fatalf("apply good config: %v\n%v", err, s.Status().Log)
	}
	err = s.Apply(clash, []byte(`{"v":2}`))
	var re *ReloadError
	if !errors.As(err, &re) {
		t.Fatalf("apply clashing config: err = %v, want *ReloadError\n%v", err, s.Status().Log)
	}
	if got := readConf(t, s); got != good {
		t.Fatalf("current.conf not restored:\n%s", got)
	}
	if len(s.History()) != 1 {
		t.Fatalf("history = %d, want 1", len(s.History()))
	}
}
