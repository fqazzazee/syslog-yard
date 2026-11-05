package engine

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/syslog-yard/syslog-hose/internal/preset"
)

type testCert struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	der  []byte
}

func (c testCert) pem() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.der}))
}

func (c testCert) serverConfig() *tls.Config {
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{c.der}, PrivateKey: c.key}}}
}

// newCert issues a certificate from tmpl, signed by parent (nil = self-signed).
func newCert(t *testing.T, tmpl *x509.Certificate, parent *testCert) testCert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := crand.Int(crand.Reader, big.NewInt(1<<62))
	tmpl.SerialNumber = serial
	tmpl.NotBefore = time.Now().Add(-time.Hour)
	tmpl.NotAfter = time.Now().Add(time.Hour)
	tmpl.BasicConstraintsValid = true
	signer, signerCert := key, tmpl
	if parent != nil {
		signer, signerCert = parent.key, parent.cert
	}
	der, err := x509.CreateCertificate(crand.Reader, tmpl, signerCert, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return testCert{cert: cert, key: key, der: der}
}

func newCA(t *testing.T) testCert {
	return newCert(t, &x509.Certificate{
		Subject:  pkix.Name{CommonName: "test CA"},
		IsCA:     true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}, nil)
}

func serverLeaf(t *testing.T, ca *testCert, dnsNames []string, ips ...string) testCert {
	tmpl := &x509.Certificate{
		Subject:     pkix.Name{CommonName: "receiver"},
		DNSNames:    dnsNames,
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, ip := range ips {
		tmpl.IPAddresses = append(tmpl.IPAddresses, net.ParseIP(ip))
	}
	return newCert(t, tmpl, ca)
}

// tlsReceiver serves TLS on loopback and forwards each frame it reads.
func tlsReceiver(t *testing.T, conf *tls.Config) (int, <-chan string) {
	t.Helper()
	l, err := tls.Listen("tcp", "127.0.0.1:0", conf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	ch := make(chan string, 10)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					msg, err := readFrame(br)
					if err != nil {
						return
					}
					ch <- msg
				}
			}()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port, ch
}

// sendOnce sends one message over a fresh TLS sender built from the job's
// TLS fields and reports the send error, after checking delivery.
func sendOnce(t *testing.T, port int, got <-chan string, insecure bool, ca, serverName string) error {
	t.Helper()
	conf, err := TLSConfig(insecure, ca, serverName)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSender(context.Background(), "tls", "127.0.0.1", port, conf)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Send("hello"); err != nil {
		return err
	}
	select {
	case msg := <-got:
		if msg != "hello" {
			t.Fatalf("received %q", msg)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("message never arrived")
	}
	return nil
}

func TestTLSSenderTrustsCustomCA(t *testing.T) {
	ca := newCA(t)
	leaf := serverLeaf(t, &ca, []string{"syslog-valve"}, "127.0.0.1")
	port, got := tlsReceiver(t, leaf.serverConfig())

	if err := sendOnce(t, port, got, false, ca.pem(), ""); err != nil {
		t.Fatalf("with the CA trusted: %v", err)
	}
	if err := sendOnce(t, port, got, false, "", ""); err == nil {
		t.Fatal("system roots accepted a private CA")
	}
	other := newCA(t)
	if err := sendOnce(t, port, got, false, other.pem(), ""); err == nil {
		t.Fatal("an unrelated CA was accepted")
	}
	// a bundle holding the right CA among others works
	if err := sendOnce(t, port, got, false, other.pem()+"\n# comment\n"+ca.pem(), ""); err != nil {
		t.Fatalf("with a bundle: %v", err)
	}
}

func TestTLSSenderServerNameOverride(t *testing.T) {
	ca := newCA(t)
	leaf := serverLeaf(t, &ca, []string{"syslog-valve"}) // no IP SAN
	port, got := tlsReceiver(t, leaf.serverConfig())

	if err := sendOnce(t, port, got, false, ca.pem(), ""); err == nil || !strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("dialing by IP without an override: %v, want a name mismatch", err)
	}
	if err := sendOnce(t, port, got, false, ca.pem(), "syslog-valve"); err != nil {
		t.Fatalf("with the override: %v", err)
	}
	if err := sendOnce(t, port, got, false, ca.pem(), "elsewhere.example"); err == nil {
		t.Fatal("a wrong override was accepted")
	}
}

// Pinning: the valve's self-signed certificate is not a CA, but trusting it
// directly verifies it.
func TestTLSSenderPinsSelfSignedLeaf(t *testing.T) {
	leaf := newCert(t, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "syslog-valve"},
		DNSNames:    []string{"syslog-valve", "localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, nil)
	port, got := tlsReceiver(t, leaf.serverConfig())
	if err := sendOnce(t, port, got, false, leaf.pem(), ""); err != nil {
		t.Fatalf("pinned certificate: %v", err)
	}
	if err := sendOnce(t, port, got, false, "", ""); err == nil {
		t.Fatal("unpinned self-signed certificate was accepted")
	}
}

func TestParseTrustedCerts(t *testing.T) {
	ca := newCA(t)
	keyDER, _ := x509.MarshalECPrivateKey(ca.key)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	truncated := ca.pem()[:len(ca.pem())-30]
	for _, c := range []struct {
		name, in, want string
	}{
		{"empty", "", "no PEM certificate"},
		{"garbage", "not a certificate", "no PEM certificate"},
		{"private key", keyPEM, "private key"},
		{"key after cert", ca.pem() + keyPEM, "private key"},
		{"wrong block", string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte{1}})), "unexpected PEM block"},
		{"bad DER", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2, 3}})), "certificate 1"},
		{"truncated", ca.pem() + truncated, "malformed PEM"},
		{"oversized", strings.Repeat(ca.pem(), MaxTLSCA/len(ca.pem())+1), "larger than"},
	} {
		if _, err := ParseTrustedCerts(c.in); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.want)
		}
	}
	certs, err := ParseTrustedCerts("leading text\n" + ca.pem() + "\n" + ca.pem())
	if err != nil || len(certs) != 2 {
		t.Fatalf("two certificates: %d, %v", len(certs), err)
	}
}

func TestValidateTLSFields(t *testing.T) {
	ca := newCA(t)
	base := JobConfig{Name: "j", Host: "h", Port: 6514, Transport: "tls", Rate: 1}
	for _, c := range []struct {
		name   string
		mutate func(*JobConfig)
		want   string // "" = valid
	}{
		{"no TLS fields", func(*JobConfig) {}, ""},
		{"CA", func(c *JobConfig) { c.TLSCA = "\n" + ca.pem() + "\n" }, ""},
		{"CA and server name", func(c *JobConfig) { c.TLSCA, c.TLSServerName = ca.pem(), "syslog-valve" }, ""},
		{"bad CA", func(c *JobConfig) { c.TLSCA = "nope" }, "no PEM certificate"},
		{"CA plus insecure", func(c *JobConfig) { c.TLSCA, c.TLSInsecure = ca.pem(), true }, "exclude each other"},
		{"kept CA on udp, insecure left on", func(c *JobConfig) { c.Transport, c.TLSCA, c.TLSInsecure = "udp", ca.pem(), true }, ""},
		{"bad CA on udp", func(c *JobConfig) { c.Transport, c.TLSCA = "udp", "nope" }, "no PEM certificate"},
		{"server name with space", func(c *JobConfig) { c.TLSServerName = "a b" }, "host name"},
		{"server name with slash", func(c *JobConfig) { c.TLSServerName = "a/b" }, "host name"},
		{"server name too long", func(c *JobConfig) { c.TLSServerName = strings.Repeat("a", 254) }, "253"},
	} {
		cfg := base
		c.mutate(&cfg)
		err := cfg.Validate()
		if c.want == "" && err != nil {
			t.Errorf("%s: unexpected error %v", c.name, err)
		}
		if c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.want)
		}
	}
	cfg := base
	cfg.TLSCA, cfg.TLSServerName = "  "+ca.pem()+"\n\n", " syslog-valve "
	if err := cfg.Validate(); err != nil || strings.TrimSpace(cfg.TLSCA) != cfg.TLSCA || cfg.TLSServerName != "syslog-valve" {
		t.Fatalf("Validate did not trim: %v %q %q", err, cfg.TLSCA, cfg.TLSServerName)
	}
}

// jobs.json written before tlsCA/tlsServerName existed loads as-is, and a
// job that does not use them persists exactly as before.
func TestJobsJSONBackwardCompatible(t *testing.T) {
	const old = `[{"id":"a1","name":"edge","preset":"none","host":"syslog-valve","port":6514,` +
		`"transport":"tls","tlsInsecure":true,"format":"","rate":5,"rateMode":"steady",` +
		`"jitterPct":30,"burstFactor":5,"burstEvery":30,"burstLen":5,"durationSec":0,` +
		`"maxEvents":0,"hostname":"","appname":"","facility":-1,"autostart":false}]`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "jobs.json"), []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	store, err := preset.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mgr, err := NewManager(store, dir)
	if err != nil {
		t.Fatal(err)
	}
	jobs := mgr.List()
	if len(jobs) != 1 || !jobs[0].TLSInsecure || jobs[0].TLSCA != "" {
		t.Fatalf("loaded %+v", jobs)
	}
	again, _ := json.Marshal([]JobConfig{jobs[0].JobConfig})
	var want, got any
	json.Unmarshal([]byte(old), &want)
	json.Unmarshal(again, &got)
	if !reflect.DeepEqual(want, got) {
		t.Fatalf("re-encoded job differs:\n got %s\nwant %s", again, old)
	}
}
