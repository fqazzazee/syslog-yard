package certs

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// A failure while preparing the new pair must leave the old one intact, or
// syslog-ng's next reload would load a key that doesn't match its cert.
func TestGenerateFailureKeepsExistingPair(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "v.crt"), filepath.Join(dir, "v.key")
	if err := GenerateSelfSigned(cert, key, []string{"a"}); err != nil {
		t.Fatal(err)
	}
	oldKey, _ := os.ReadFile(key)
	oldCert, _ := os.ReadFile(cert)
	// The cert's temp path being a directory makes staging it fail.
	if err := os.Mkdir(cert+".tmp", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := GenerateSelfSigned(cert, key, []string{"b"}); err == nil {
		t.Fatal("want an error")
	}
	newKey, _ := os.ReadFile(key)
	newCert, _ := os.ReadFile(cert)
	if !bytes.Equal(oldKey, newKey) || !bytes.Equal(oldCert, newCert) {
		t.Fatal("failed generation changed the existing pair")
	}
	if _, err := os.Stat(key + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("staged key left behind: %v", err)
	}
}
