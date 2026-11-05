package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHealthURL(t *testing.T) {
	for addr, want := range map[string]string{
		":8080":         "http://127.0.0.1:8080/api/healthz",
		"0.0.0.0:9000":  "http://127.0.0.1:9000/api/healthz",
		"[::]:8080":     "http://127.0.0.1:8080/api/healthz",
		"10.1.2.3:8080": "http://10.1.2.3:8080/api/healthz",
		"localhost:80":  "http://localhost:80/api/healthz",
	} {
		if got := healthURL(addr); got != want {
			t.Errorf("healthURL(%q) = %q, want %q", addr, got, want)
		}
	}
}

func TestHealthcheckExitCode(t *testing.T) {
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/healthz" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer ok.Close()
	addr := strings.TrimPrefix(ok.URL, "http://")
	if code := healthcheck(addr); code != 0 {
		t.Fatalf("healthy server: exit %d", code)
	}

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer bad.Close()
	if code := healthcheck(strings.TrimPrefix(bad.URL, "http://")); code != 1 {
		t.Fatalf("unhealthy server: exit %d", code)
	}

	bad.Close()
	if code := healthcheck(strings.TrimPrefix(bad.URL, "http://")); code != 1 {
		t.Fatalf("down server: exit %d", code)
	}
}
