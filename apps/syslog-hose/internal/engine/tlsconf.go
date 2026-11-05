package engine

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"unicode"
)

// MaxTLSCA caps a job's pasted CA bundle or pinned certificate. A chain
// of a handful of certificates is a few KiB.
const MaxTLSCA = 64 << 10

// ParseTrustedCerts parses a job's tlsCA: PEM text holding one or more
// CERTIFICATE blocks (a CA bundle, or the receiver's own certificate to
// pin it). Text around the blocks is ignored, as in ca-certificates
// bundles; anything else that looks like PEM is an error, and a private
// key is refused outright so it is never stored with the job.
func ParseTrustedCerts(pemText string) ([]*x509.Certificate, error) {
	if len(pemText) > MaxTLSCA {
		return nil, fmt.Errorf("tlsCA is larger than %d bytes", MaxTLSCA)
	}
	var certs []*x509.Certificate
	rest := []byte(pemText)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if strings.Contains(block.Type, "PRIVATE KEY") {
			return nil, fmt.Errorf("tlsCA holds a private key: paste only the certificate")
		}
		if block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("tlsCA: unexpected PEM block %q, want CERTIFICATE", block.Type)
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("tlsCA: certificate %d: %v", len(certs)+1, err)
		}
		certs = append(certs, cert)
	}
	if bytes.Contains(rest, []byte("-----BEGIN")) {
		return nil, fmt.Errorf("tlsCA: malformed PEM block after certificate %d", len(certs))
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("tlsCA: no PEM certificate found (expected -----BEGIN CERTIFICATE-----)")
	}
	return certs, nil
}

// checkServerName validates a tlsServerName override: a host name or IP
// address, as it would appear in the certificate.
func checkServerName(name string) error {
	if len(name) > 253 {
		return fmt.Errorf("tlsServerName is longer than 253 characters")
	}
	for _, r := range name {
		if unicode.IsSpace(r) || unicode.IsControl(r) || strings.ContainsRune("/\\@?#", r) {
			return fmt.Errorf("tlsServerName must be a host name or IP address")
		}
	}
	return nil
}

// TLSConfig builds the client TLS settings for a job. With caPEM set, the
// receiver must present a chain to one of those certificates (a pinned
// leaf certificate counts as its own root) instead of one to the system
// roots. serverName overrides the name the certificate is checked
// against, which otherwise is the destination host.
func TLSConfig(insecure bool, caPEM, serverName string) (*tls.Config, error) {
	conf := &tls.Config{InsecureSkipVerify: insecure, ServerName: serverName}
	if strings.TrimSpace(caPEM) != "" {
		certs, err := ParseTrustedCerts(caPEM)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		for _, c := range certs {
			pool.AddCert(c)
		}
		conf.RootCAs = pool
	}
	return conf, nil
}
