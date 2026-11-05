package rotate

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRunWithoutConfigIsNoop(t *testing.T) {
	dir := t.TempDir()
	r := &Rotator{ConfPath: filepath.Join(dir, "missing.conf"), StatePath: filepath.Join(dir, "state")}
	if out, err := r.Run(); err != nil || out == "" {
		t.Fatalf("missing config: %q, %v", out, err)
	}
	os.WriteFile(r.ConfPath, []byte("  \n"), 0o644)
	if _, err := r.Run(); err != nil {
		t.Fatalf("empty config: %v", err)
	}
}

func TestRunRotates(t *testing.T) {
	if _, err := exec.LookPath("logrotate"); err != nil {
		t.Skip("logrotate not installed")
	}
	dir := t.TempDir()
	log := filepath.Join(dir, "my cache", "messages.log")
	os.MkdirAll(filepath.Dir(log), 0o755)
	os.WriteFile(log, []byte("hello\n"), 0o644)
	r := &Rotator{ConfPath: filepath.Join(dir, "logrotate.conf"), StatePath: filepath.Join(dir, "state")}
	conf := "\"" + log + "\" {\n    missingok\n    copytruncate\n    rotate 2\n    size 1\n}\n"
	os.WriteFile(r.ConfPath, []byte(conf), 0o644)
	if _, err := r.Run(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(log + ".1"); err != nil {
		t.Fatalf("log not rotated: %v", err)
	}
}
