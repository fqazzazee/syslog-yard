package supervisor

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// fakeScript is a stand-in for syslog-ng, so the supervisor can be tested
// without it installed. --syntax-only rejects configs containing BAD. Run in
// the foreground it mimics syslog-ng's reload log lines on SIGHUP: a config
// containing CLASH fails to initialise (like a port already in use), SILENT
// never reports back. A config containing DIE exits at once after printing
// two lines; HANG ignores SIGTERM.
const fakeScript = `#!/bin/sh
if [ "$1" = "--version" ]; then echo "syslog-ng 4 (4.8.1)"; exit 0; fi
if [ "$1" = "--syntax-only" ]; then
  if grep -q BAD "$3"; then echo "test-parse-error in $3" >&2; exit 1; fi
  exit 0
fi
conf="$5"
if grep -q DIE "$conf"; then
  echo "[t] Error binding socket; error='Address already in use (98)'" >&2
  printf "[t] last words before exit" >&2
  exit 2
fi
hup() {
  if grep -q CLASH "$conf"; then
    echo "[t] Error binding socket; addr='AF_INET(0.0.0.0:514)', error='Address already in use (98)'" >&2
    echo "[t] Error initializing new configuration, reverting to old config;" >&2
    echo "[t] Configuration reload finished;" >&2
  elif grep -q SILENT "$conf"; then
    :
  else
    echo "[t] Loading the new configuration;" >&2
    echo "[t] Configuration reload finished;" >&2
  fi
}
trap hup HUP
if grep -q HANG "$conf"; then trap '' TERM; else trap 'exit 0' TERM; fi
echo "[t] syslog-ng starting up" >&2
while :; do sleep 0.05; done
`

func fakeSyslogNG(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "syslog-ng")
	if err := os.WriteFile(bin, []byte(fakeScript), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func logHas(s *Supervisor, sub string) bool {
	return slices.ContainsFunc(s.Status().Log, func(l string) bool { return strings.Contains(l, sub) })
}

// started returns a supervisor running the fake with initial config conf.
func started(t *testing.T, conf string) *Supervisor {
	t.Helper()
	s := New(fakeSyslogNG(t), t.TempDir())
	if err := s.Start(context.Background(), conf); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Shutdown)
	return s
}

func readConf(t *testing.T, s *Supervisor) string {
	t.Helper()
	data, err := os.ReadFile(s.ConfPath())
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestValidate(t *testing.T) {
	s := New(fakeSyslogNG(t), t.TempDir())
	if err := s.Validate("@version: 4.8\n"); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	if err := s.Validate("BAD config"); err == nil {
		t.Fatal("invalid config accepted")
	}
}

func TestVersionParsing(t *testing.T) {
	s := New(fakeSyslogNG(t), t.TempDir())
	if v := s.Version(); v != "4.8" {
		t.Fatalf("version = %q, want 4.8", v)
	}
}

func TestApplyConfirmedAndRejectedReload(t *testing.T) {
	s := started(t, "initial")
	waitFor(t, "startup", func() bool { return logHas(s, "starting up") })

	// Syntax failure: nothing changes.
	if err := s.Apply("BAD", []byte(`{}`)); err == nil {
		t.Fatal("apply accepted invalid config")
	}
	if got := readConf(t, s); got != "initial" || len(s.History()) != 0 {
		t.Fatalf("failed syntax check changed state: conf=%q history=%d", got, len(s.History()))
	}

	if err := s.Apply("conf-v1", []byte(`{"v":1}`)); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if got := readConf(t, s); got != "conf-v1" || len(s.History()) != 1 {
		t.Fatalf("after apply: conf=%q history=%d", got, len(s.History()))
	}

	// Passes --syntax-only but syslog-ng refuses it at reload: the API must
	// see an error and current.conf must go back to what is still running.
	err := s.Apply("conf-v2 CLASH", []byte(`{"v":2}`))
	var re *ReloadError
	if !errors.As(err, &re) {
		t.Fatalf("apply of runtime-bad config: err = %v, want *ReloadError", err)
	}
	if !strings.Contains(re.Error(), "Address already in use") {
		t.Errorf("reload error lacks syslog-ng's reason: %v", re)
	}
	if got := readConf(t, s); got != "conf-v1" {
		t.Fatalf("current.conf = %q after rejected reload, want conf-v1", got)
	}
	if len(s.History()) != 1 {
		t.Fatalf("rejected config archived: history=%d", len(s.History()))
	}
	if s.Status().LastError == "" {
		t.Error("LastError not set")
	}
	if !s.Status().Running {
		t.Error("syslog-ng should still be running")
	}

	// The active graph is the one archived with the running config.
	data, _, ok := s.ActiveGraph()
	if !ok || string(data) != `{"v":1}` {
		t.Fatalf("ActiveGraph = %q, %v", data, ok)
	}
	if g, err := s.HistoryGraph(s.History()[0].ID); err != nil || string(g) != `{"v":1}` {
		t.Fatalf("HistoryGraph = %q, %v", g, err)
	}
}

func TestApplyReloadTimeout(t *testing.T) {
	s := started(t, "initial")
	s.ReloadTimeout = 300 * time.Millisecond
	waitFor(t, "startup", func() bool { return logHas(s, "starting up") })
	if err := s.Apply("SILENT", []byte(`{}`)); err == nil || !strings.Contains(err.Error(), "did not confirm") {
		t.Fatalf("err = %v, want timeout", err)
	}
	if got := readConf(t, s); got != "initial" {
		t.Fatalf("current.conf = %q, want initial restored", got)
	}
	if len(s.History()) != 0 {
		t.Fatal("unconfirmed config archived")
	}
}

func TestApplyWhileNotRunning(t *testing.T) {
	s := New(fakeSyslogNG(t), t.TempDir())
	if err := os.MkdirAll(s.historyDir(), 0o755); err != nil {
		t.Fatal(err)
	}
	// Installing a config must still work when syslog-ng is down (that is
	// how a crash loop gets fixed), but the caller is told it's unconfirmed.
	err := s.Apply("conf-v1", []byte(`{"v":1}`))
	if !errors.Is(err, ErrNotRunning) {
		t.Fatalf("err = %v, want ErrNotRunning", err)
	}
	if got := readConf(t, s); got != "conf-v1" {
		t.Fatalf("current.conf = %q", got)
	}
	if len(s.History()) != 1 {
		t.Fatal("config not archived")
	}
}

func TestLastLinesBeforeExitAreKept(t *testing.T) {
	s := started(t, "DIE")
	// The final line has no trailing newline and is written right before
	// exit; it must still reach the log ring.
	waitFor(t, "final output line", func() bool { return logHas(s, "last words before exit") })
	waitFor(t, "exit recorded", func() bool { return strings.Contains(s.Status().LastError, "exited") })
}

func TestShutdownKillsHungChild(t *testing.T) {
	s := New(fakeSyslogNG(t), t.TempDir())
	s.StopTimeout = 300 * time.Millisecond
	if err := s.Start(context.Background(), "HANG"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "startup", func() bool { return logHas(s, "starting up") })
	done := make(chan struct{})
	go func() { s.Shutdown(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Shutdown blocked on a child that ignores SIGTERM")
	}
}

func TestLineWriter(t *testing.T) {
	var got []string
	w := &lineWriter{emit: func(s string) { got = append(got, s) }}
	w.Write([]byte("a\nb"))
	w.Write([]byte("c\nd"))
	w.flush()
	if strings.Join(got, "|") != "a|bc|d" {
		t.Fatalf("lines = %q", got)
	}
}
