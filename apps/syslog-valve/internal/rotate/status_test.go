package rotate

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLastErrorTracksRuns(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "logrotate")
	write := func(body string) {
		t.Helper()
		// Replace rather than rewrite, so a just-run script is never busy.
		os.Remove(bin)
		if err := os.WriteFile(bin, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	conf := filepath.Join(dir, "lr.conf")
	if err := os.WriteFile(conf, []byte("x {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := &Rotator{ConfPath: conf, StatePath: filepath.Join(dir, "state")}

	write("echo 'error: insecure permissions' >&2; exit 1")
	if _, err := r.Run(); err == nil {
		t.Fatal("want an error")
	}
	if got := r.LastError(); !strings.Contains(got, "insecure permissions") {
		t.Fatalf("LastError = %q", got)
	}

	write("exit 0")
	if _, err := r.Run(); err != nil {
		t.Fatal(err)
	}
	if got := r.LastError(); got != "" {
		t.Fatalf("LastError after success = %q", got)
	}
}
