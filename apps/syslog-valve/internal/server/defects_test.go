package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/syslog-yard/syslog-valve/internal/graph"
	"github.com/syslog-yard/syslog-valve/internal/supervisor"
)

func TestPutGraphRejectsMissingOrNullLists(t *testing.T) {
	e := newEnv(t)
	valid := flow("keep", false, 5514)
	e.mustOK("PUT", "/api/graph", valid)
	saved := e.read("graph.json")
	for _, body := range []string{
		`{}`, `null`, `{"name":"some-package","version":"1.0.0"}`,
		`{"nodes":[]}`, `{"edges":[]}`,
		`{"nodes":null,"edges":[]}`, `{"nodes":[],"edges":null}`,
	} {
		if rec := e.do("PUT", "/api/graph", []byte(body)); rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("PUT %s: got %d, want 422", body, rec.Code)
		}
		if got := e.read("graph.json"); got != saved {
			t.Fatalf("PUT %s changed the saved graph to %s", body, got)
		}
	}
}

func TestPutGraphAcceptsExplicitEmptyLists(t *testing.T) {
	e := newEnv(t)
	e.mustOK("PUT", "/api/graph", []byte(`{"nodes":[],"edges":[]}`))
	if got := strings.TrimSpace(e.read("graph.json")); got != `{"nodes":[],"edges":[]}` {
		t.Fatalf("saved %s", got)
	}
}

func TestPutGraphStoresNormalizedJSON(t *testing.T) {
	e := newEnv(t)
	var doc map[string]any
	if err := json.Unmarshal(flow("keep", false, 5514), &doc); err != nil {
		t.Fatal(err)
	}
	doc["name"] = "stray"
	body, _ := json.MarshalIndent(doc, "", "    ")
	e.mustOK("PUT", "/api/graph", body)
	got := e.read("graph.json")
	if strings.Contains(got, "stray") || strings.Contains(got, "\n") {
		t.Fatalf("stored graph not normalized: %s", got)
	}
	if _, err := graph.Parse([]byte(got)); err != nil {
		t.Fatal(err)
	}
}

func reloads(e *env) int {
	n := 0
	for _, l := range e.sup.Status().Log {
		if strings.Contains(l, "Configuration reload finished") {
			n++
		}
	}
	return n
}

func TestCertGenerateReloadsSyslogNG(t *testing.T) {
	e := newEnv(t)
	e.srv.genCert = func([]string) error { return nil }
	before := reloads(e)
	e.mustOK("POST", "/api/certs/selfsigned", []byte(`{}`))
	if got := reloads(e); got != before+1 {
		t.Fatalf("reloads = %d, want %d", got, before+1)
	}
}

func TestCertGenerateReportsFailedReload(t *testing.T) {
	e := newEnv(t)
	e.srv.genCert = func([]string) error { return nil }
	// The fake refuses any config mentioning this port at reload time.
	if err := os.WriteFile(e.sup.ConfPath(), []byte("port(5999)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rec := e.do("POST", "/api/certs/selfsigned", []byte(`{}`))
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "previous") {
		t.Fatalf("got %d %s", rec.Code, rec.Body)
	}
}

func TestCertGenerateWithoutRunningSyslogNG(t *testing.T) {
	dataDir := t.TempDir()
	sup := supervisor.New(filepath.Join(dataDir, "absent"), filepath.Join(dataDir, "syslog-ng"))
	srv := New(sup, dataDir, nil, nil, nil, nil, nil, nil, nil)
	srv.genCert = func([]string) error { return nil }
	e := &env{t: t, dataDir: dataDir, sup: sup, srv: srv}
	e.mustOK("POST", "/api/certs/selfsigned", []byte(`{}`))
}

func TestCertGenerateFailureSkipsReload(t *testing.T) {
	e := newEnv(t)
	e.srv.genCert = func([]string) error { return errors.New("disk full") }
	before := reloads(e)
	if rec := e.do("POST", "/api/certs/selfsigned", []byte(`{}`)); rec.Code != http.StatusInternalServerError {
		t.Fatalf("got %d", rec.Code)
	}
	if got := reloads(e); got != before {
		t.Fatalf("reloaded after a failed generation")
	}
}

func TestStatusReportsRotationFailure(t *testing.T) {
	e := newEnv(t)
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "logrotate"), []byte("#!/bin/sh\necho 'insecure permissions' >&2\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	if err := os.WriteFile(e.rotator.ConfPath, []byte("x {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := e.rotator.Run(); err == nil {
		t.Fatal("want a rotation error")
	}
	var st struct {
		RotateError string `json:"rotateError"`
	}
	if err := json.Unmarshal(e.mustOK("GET", "/api/status", nil).Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(st.RotateError, "insecure permissions") {
		t.Fatalf("rotateError = %q", st.RotateError)
	}
}
