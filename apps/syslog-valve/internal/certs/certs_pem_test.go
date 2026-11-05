package certs

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPublicPEMNeverServesTheKey(t *testing.T) {
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "valve.crt"), filepath.Join(dir, "valve.key")

	if _, err := PublicPEM(certFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing file: %v, want ErrNotExist", err)
	}

	if err := GenerateSelfSigned(certFile, keyFile, []string{"syslog-valve", "127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	got, err := PublicPEM(certFile)
	if err != nil {
		t.Fatal(err)
	}
	block, rest := pem.Decode(got)
	if block == nil || block.Type != "CERTIFICATE" || len(strings.TrimSpace(string(rest))) != 0 {
		t.Fatalf("want exactly one CERTIFICATE block, got %q", got)
	}
	if cert, err := x509.ParseCertificate(block.Bytes); err != nil || cert.DNSNames[0] != "syslog-valve" {
		t.Fatalf("served certificate: %v", err)
	}

	// a deployment that mounted key and certificate in one file
	key, _ := os.ReadFile(keyFile)
	crt, _ := os.ReadFile(certFile)
	combined := filepath.Join(dir, "combined.pem")
	os.WriteFile(combined, append(append([]byte("# lab pair\n"), key...), crt...), 0o600)
	got, err = PublicPEM(combined)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "PRIVATE KEY") || string(got) != string(crt) {
		t.Fatalf("combined file served %q", got)
	}

	os.WriteFile(combined, key, 0o600)
	if _, err := PublicPEM(combined); err == nil {
		t.Fatal("a key-only file was served")
	}
}
