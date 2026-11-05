package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/syslog-yard/syslog-hose/internal/engine"
	"github.com/syslog-yard/syslog-hose/internal/preset"
)

// testCertPEM returns a self-signed certificate like the valve's, and its
// key as PEM.
func testCertPEM(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "syslog-valve"},
		DNSNames:              []string{"syslog-valve"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
}

func newServerWithValve(t *testing.T, valveURL string) *httptest.Server {
	t.Helper()
	store, err := preset.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mgr, err := engine.NewManager(store, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := New(mgr, store, nil, nil, nil)
	s.SetValveURL(valveURL)
	ts := httptest.NewServer(s)
	t.Cleanup(ts.Close)
	return ts
}

func TestValveCert(t *testing.T) {
	certPEM, keyPEM := testCertPEM(t)
	var answer func(w http.ResponseWriter)
	valve := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/certs/pem" {
			http.NotFound(w, r)
			return
		}
		answer(w)
	}))
	t.Cleanup(valve.Close)
	ts := newServerWithValve(t, valve.URL+"/")

	if code, body := do(t, "GET", ts.URL+"/api/hints", ""); code != 200 || !strings.Contains(string(body), `"valveCert":"true"`) {
		t.Fatalf("hints: %d %s", code, body)
	}

	answer = func(w http.ResponseWriter) { w.Write([]byte("junk before\n" + certPEM)) }
	code, body := do(t, "GET", ts.URL+"/api/valve-cert", "")
	var got struct {
		PEM   string   `json:"pem"`
		Names []string `json:"names"`
	}
	if code != 200 || json.Unmarshal(body, &got) != nil {
		t.Fatalf("valve-cert: %d %s", code, body)
	}
	if got.PEM != certPEM || len(got.Names) != 1 || got.Names[0] != "syslog-valve" {
		t.Fatalf("valve-cert answered %+v", got)
	}

	for _, c := range []struct {
		name   string
		answer func(w http.ResponseWriter)
		code   int
		want   string
	}{
		{"no cert yet", func(w http.ResponseWriter) {
			w.WriteHeader(404)
			w.Write([]byte(`{"error":"the valve has no TLS certificate yet: generate one"}`))
		}, 404, "generate one"},
		{"key instead of cert", func(w http.ResponseWriter) { w.Write([]byte(keyPEM)) }, 502, "private key"},
		{"valve error", func(w http.ResponseWriter) { w.WriteHeader(500) }, 502, "500"},
		{"redirect not followed", func(w http.ResponseWriter) {
			w.Header().Set("Location", "http://169.254.169.254/")
			w.WriteHeader(302)
		}, 502, "302"},
	} {
		answer = c.answer
		code, body := do(t, "GET", ts.URL+"/api/valve-cert", "")
		if code != c.code || !strings.Contains(string(body), c.want) {
			t.Errorf("%s: %d %s", c.name, code, body)
		}
		if strings.Contains(string(body), "PRIVATE KEY") {
			t.Errorf("%s: key material relayed: %s", c.name, body)
		}
	}

	off := newServerWithValve(t, "")
	if code, body := do(t, "GET", off.URL+"/api/valve-cert", ""); code != 404 || !strings.Contains(string(body), "HOSE_VALVE_URL") {
		t.Fatalf("unconfigured: %d %s", code, body)
	}
	if _, body := do(t, "GET", off.URL+"/api/hints", ""); strings.Contains(string(body), "valveCert") {
		t.Fatalf("unconfigured hints: %s", body)
	}
}

// Job saves validate the TLS trust fields and keep them.
func TestJobTLSFields(t *testing.T) {
	ts := newTestServer(t, nil)
	certPEM, keyPEM := testCertPEM(t)
	job := func(extra map[string]any) string {
		m := map[string]any{"name": "tls", "preset": "linux-host", "host": "127.0.0.1", "port": 6514, "transport": "tls", "rate": 1}
		for k, v := range extra {
			m[k] = v
		}
		b, _ := json.Marshal(m)
		return string(b)
	}
	for _, c := range []struct {
		name  string
		extra map[string]any
		want  string
	}{
		{"not PEM", map[string]any{"tlsCA": "hello"}, "no PEM certificate"},
		{"private key", map[string]any{"tlsCA": keyPEM}, "private key"},
		{"cert and key", map[string]any{"tlsCA": certPEM + keyPEM}, "private key"},
		{"with insecure", map[string]any{"tlsCA": certPEM, "tlsInsecure": true}, "exclude each other"},
		{"bad server name", map[string]any{"tlsCA": certPEM, "tlsServerName": "a b"}, "host name"},
	} {
		code, body := do(t, "POST", ts.URL+"/api/jobs", job(c.extra))
		if code != 400 || !strings.Contains(string(body), c.want) {
			t.Errorf("%s: %d %s", c.name, code, body)
		}
	}

	code, body := do(t, "POST", ts.URL+"/api/jobs", job(map[string]any{"tlsCA": certPEM, "tlsServerName": "syslog-valve"}))
	var st struct {
		ID            string `json:"id"`
		TLSCA         string `json:"tlsCA"`
		TLSServerName string `json:"tlsServerName"`
	}
	if code != 201 || json.Unmarshal(body, &st) != nil || st.TLSCA != strings.TrimSpace(certPEM) || st.TLSServerName != "syslog-valve" {
		t.Fatalf("create: %d %s", code, body)
	}
	// clearing the CA again is a plain update
	if code, body := do(t, "PUT", ts.URL+"/api/jobs/"+st.ID, job(map[string]any{"tlsInsecure": true})); code != 200 || strings.Contains(string(body), "tlsCA") {
		t.Fatalf("update: %d %s", code, body)
	}
}
