package certs

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestGenerateSelfSigned(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs") // created on demand
	cert, key := filepath.Join(dir, "valve.crt"), filepath.Join(dir, "valve.key")
	if err := Require(cert, key); err == nil {
		t.Fatal("Require passed with no files")
	}
	if st := Inspect(cert); st.Exists {
		t.Fatalf("Inspect of a missing file = %+v", st)
	}

	if err := GenerateSelfSigned(cert, key, []string{"valve.lan", "192.0.2.10", "::1"}); err != nil {
		t.Fatal(err)
	}
	if err := Require(cert, key); err != nil {
		t.Errorf("Require after generate: %v", err)
	}

	// The pair loads as a TLS identity and verifies for every SAN.
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatalf("generated pair does not load: %v", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"valve.lan", "192.0.2.10", "::1"} {
		if err := leaf.VerifyHostname(h); err != nil {
			t.Errorf("certificate not valid for %s: %v", h, err)
		}
	}
	if err := leaf.VerifyHostname("other.lan"); err == nil {
		t.Error("certificate valid for a host it doesn't name")
	}
	if !slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) {
		t.Error("certificate lacks server auth usage")
	}
	if time.Until(leaf.NotAfter) < 4*365*24*time.Hour || leaf.NotBefore.After(time.Now()) {
		t.Errorf("validity %v – %v", leaf.NotBefore, leaf.NotAfter)
	}

	// The private key is owner-only; no temp files are left behind.
	if fi, err := os.Stat(key); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("key mode = %v, %v; want 0600", fi.Mode().Perm(), err)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "*.tmp")); len(left) != 0 {
		t.Errorf("temp files left: %v", left)
	}

	st := Inspect(cert)
	if !st.Exists || st.Error != "" || st.Subject != "CN=syslog-valve" {
		t.Errorf("Inspect = %+v", st)
	}
	if want := []string{"valve.lan", "192.0.2.10", "::1"}; !slices.Equal(st.SANs, want) {
		t.Errorf("SANs = %v, want %v", st.SANs, want)
	}
	if _, err := time.Parse(time.RFC3339, st.NotAfter); err != nil {
		t.Errorf("NotAfter %q: %v", st.NotAfter, err)
	}

	// Regenerating replaces the pair.
	if err := GenerateSelfSigned(cert, key, []string{"new.lan"}); err != nil {
		t.Fatal(err)
	}
	if st := Inspect(cert); !slices.Equal(st.SANs, []string{"new.lan"}) {
		t.Errorf("SANs after regenerate = %v", st.SANs)
	}
	if _, err := tls.LoadX509KeyPair(cert, key); err != nil {
		t.Errorf("regenerated pair does not load: %v", err)
	}
}

// A stale world-readable temp file from an interrupted run must not leak
// its permissions onto the new private key.
func TestGenerateKeyModeIgnoresStaleTemp(t *testing.T) {
	dir := t.TempDir()
	cert, key := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	if err := os.WriteFile(key+".tmp", []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(key+".tmp", 0o644); err != nil {
		t.Fatal(err)
	}
	if err := GenerateSelfSigned(cert, key, nil); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(key); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("key mode = %v, %v; want 0600", fi.Mode().Perm(), err)
	}
}

func TestInspectBadFiles(t *testing.T) {
	dir := t.TempDir()
	garbage := filepath.Join(dir, "garbage.pem")
	os.WriteFile(garbage, []byte("hello"), 0o644)
	if st := Inspect(garbage); !st.Exists || st.Error != "not PEM data" {
		t.Errorf("garbage: %+v", st)
	}
	badDER := filepath.Join(dir, "bad.pem")
	os.WriteFile(badDER, []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"), 0o644)
	if st := Inspect(badDER); !st.Exists || st.Error == "" {
		t.Errorf("bad DER: %+v", st)
	}
	if st := Inspect(dir); !st.Exists || st.Error == "" {
		t.Errorf("directory: %+v", st)
	}
	// Require's message tells the user what to do and where.
	err := Require(filepath.Join(dir, "missing.crt"), filepath.Join(dir, "missing.key"))
	if err == nil || !strings.Contains(err.Error(), "missing.crt") || !strings.Contains(err.Error(), "self-signed") {
		t.Errorf("Require error = %v", err)
	}
}
