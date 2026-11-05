package server

import (
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/syslog-yard/syslog-hose/internal/engine"
)

// SetValveURL points "Trust valve's certificate" at a syslog-valve's API
// base URL as reachable from this process (HOSE_VALVE_URL, e.g.
// http://syslog-valve:8081 in the compose stack) and tells the UI the
// action is available through the valveCert hint. Call it before serving.
func (s *Server) SetValveURL(u string) {
	s.valveURL = strings.TrimRight(strings.TrimSpace(u), "/")
	if s.valveURL != "" {
		s.hints["valveCert"] = "true"
	}
}

var valveClient = &http.Client{
	Timeout: 5 * time.Second,
	// the URL is the operator's; a redirect is not followed elsewhere
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// valveCert fetches the valve's public TLS certificate server-side (the
// browser can't: connect-src 'self') and returns it for the job form to
// paste into tlsCA. The valve serves certificates only, never its key; the
// PEM is parsed here too, so nothing else reaches the form.
func (s *Server) valveCert(w http.ResponseWriter, r *http.Request) {
	if s.valveURL == "" {
		writeErr(w, http.StatusNotFound, fmt.Errorf("no valve configured: set HOSE_VALVE_URL"))
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, s.valveURL+"/api/certs/pem", nil)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	resp, err := valveClient.Do(req)
	if err != nil {
		writeErr(w, http.StatusBadGateway, fmt.Errorf("valve unreachable at %s", s.valveURL))
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, engine.MaxTLSCA+1))
	if err != nil {
		writeErr(w, http.StatusBadGateway, fmt.Errorf("reading the valve's answer: %v", err))
		return
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		var e struct{ Error string }
		if json.Unmarshal(body, &e) != nil || e.Error == "" {
			e.Error = "the valve has no TLS certificate yet"
		}
		writeErr(w, http.StatusNotFound, fmt.Errorf("%s", e.Error))
		return
	default:
		writeErr(w, http.StatusBadGateway, fmt.Errorf("valve answered %s", resp.Status))
		return
	}
	certs, err := engine.ParseTrustedCerts(string(body))
	if err != nil {
		writeErr(w, http.StatusBadGateway, fmt.Errorf("valve certificate unusable: %v", err))
		return
	}
	var out []byte
	for _, c := range certs {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	leaf := certs[0]
	names := append([]string(nil), leaf.DNSNames...)
	for _, ip := range leaf.IPAddresses {
		names = append(names, ip.String())
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"pem":      string(out),
		"subject":  leaf.Subject.String(),
		"notAfter": leaf.NotAfter.UTC().Format(time.RFC3339),
		"names":    names,
	})
}
