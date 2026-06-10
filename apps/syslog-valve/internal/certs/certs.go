// Package certs manages the valve's TLS identity: one self-signed
// certificate/key pair under /data/certs, generated on demand for lab use.
// Real deployments mount their own pair at the same paths instead.
package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

type Status struct {
	Exists   bool     `json:"exists"`
	Subject  string   `json:"subject,omitempty"`
	NotAfter string   `json:"notAfter,omitempty"`
	SANs     []string `json:"sans,omitempty"`
	Error    string   `json:"error,omitempty"` // present but unreadable/garbled
}

// Inspect reports on the certificate at certFile.
func Inspect(certFile string) Status {
	data, err := os.ReadFile(certFile)
	if os.IsNotExist(err) {
		return Status{}
	}
	if err != nil {
		return Status{Exists: true, Error: err.Error()}
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return Status{Exists: true, Error: "not PEM data"}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return Status{Exists: true, Error: err.Error()}
	}
	st := Status{
		Exists:   true,
		Subject:  cert.Subject.String(),
		NotAfter: cert.NotAfter.UTC().Format(time.RFC3339),
		SANs:     append([]string(nil), cert.DNSNames...),
	}
	for _, ip := range cert.IPAddresses {
		st.SANs = append(st.SANs, ip.String())
	}
	return st
}

// GenerateSelfSigned writes a fresh ECDSA P-256 pair valid for five years,
// replacing any existing files. hosts become DNS/IP SANs.
func GenerateSelfSigned(certFile, keyFile string, hosts []string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "syslog-valve"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(5, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(certFile), 0o755); err != nil {
		return err
	}
	if err := writePEM(keyFile, "EC PRIVATE KEY", keyDER, 0o600); err != nil {
		return err
	}
	return writePEM(certFile, "CERTIFICATE", der, 0o644)
}

func writePEM(path, blockType string, der []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return nil
}

// Require returns a friendly error when the identity files are missing.
func Require(certFile, keyFile string) error {
	for _, p := range []string{certFile, keyFile} {
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("a TLS IN port needs the valve's certificate: generate a self-signed one in the node panel, or mount cert+key at %s and %s", certFile, keyFile)
		}
	}
	return nil
}
