package supervisor

import (
	"os"
	"path/filepath"
	"testing"
)

// fakeSyslogNG writes a stub binary that accepts any config not containing
// the word BAD, so Validate/Apply can be tested without syslog-ng installed.
func fakeSyslogNG(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "syslog-ng")
	script := `#!/bin/sh
if [ "$1" = "--version" ]; then echo "syslog-ng 4 (4.8.1)"; exit 0; fi
# --syntax-only -f <file>
if grep -q BAD "$3"; then echo "test-parse-error in $3" >&2; exit 1; fi
exit 0
`
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
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

func TestApplyHistoryAndRollback(t *testing.T) {
	dir := t.TempDir()
	s := New(fakeSyslogNG(t), dir)
	if err := os.MkdirAll(s.historyDir(), 0o755); err != nil {
		t.Fatal(err)
	}

	// Apply fails on invalid config and leaves nothing behind.
	if err := s.Apply("BAD", []byte(`{}`)); err == nil {
		t.Fatal("apply accepted invalid config")
	}
	if len(s.History()) != 0 {
		t.Fatal("failed apply left history entries")
	}

	// Reload fails (no process) but the config must still be swapped in.
	if err := s.Apply("conf-v1", []byte(`{"v":1}`)); err == nil {
		t.Fatal("expected reload error with no process running")
	}
	got, _ := os.ReadFile(s.ConfPath())
	if string(got) != "conf-v1" {
		t.Fatalf("current.conf = %q, want conf-v1", got)
	}
	h := s.History()
	if len(h) != 1 {
		t.Fatalf("history has %d entries, want 1", len(h))
	}

	s.Apply("conf-v2", []byte(`{"v":2}`))
	graphJSON, err := s.Rollback(h[0].ID)
	if err != nil && string(graphJSON) == "" {
		// reload error is expected; graph must still come back
		t.Fatalf("rollback did not return graph: %v", err)
	}
	if string(graphJSON) != `{"v":1}` {
		t.Fatalf("rollback graph = %q, want {\"v\":1}", graphJSON)
	}
	got, _ = os.ReadFile(s.ConfPath())
	if string(got) != "conf-v1" {
		t.Fatalf("after rollback current.conf = %q, want conf-v1", got)
	}
}
