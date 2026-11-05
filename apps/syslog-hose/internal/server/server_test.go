package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/syslog-yard/shared/yardauth"
	"github.com/syslog-yard/syslog-hose/internal/engine"
	"github.com/syslog-yard/syslog-hose/internal/preset"
)

func newTestServer(t *testing.T, guard *yardauth.Guard) *httptest.Server {
	t.Helper()
	store, err := preset.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mgr, err := engine.NewManager(store, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(New(mgr, store, nil, nil, guard))
	t.Cleanup(func() {
		ts.Close()
		mgr.StopAll()
	})
	return ts
}

func do(t *testing.T, method, url, body string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		// secure.Headers rejects non-JSON bodies on state-changing requests.
		req.Header.Set("Content-Type", "application/json")
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

func TestHealthzOpenAndPublicUnderAuth(t *testing.T) {
	open := newTestServer(t, nil)
	code, body := do(t, "GET", open.URL+"/api/healthz", "")
	var got map[string]any
	if code != 200 || json.Unmarshal(body, &got) != nil || got["ok"] != true {
		t.Fatalf("healthz: %d %s", code, body)
	}

	// with yard auth on, healthz stays reachable without a session while
	// the rest of the API does not
	guarded := newTestServer(t, yardauth.New("http://127.0.0.1:1", false))
	if code, body := do(t, "GET", guarded.URL+"/api/healthz", ""); code != 200 {
		t.Fatalf("guarded healthz: %d %s", code, body)
	}
	if code, _ := do(t, "GET", guarded.URL+"/api/jobs", ""); code == 200 {
		t.Fatal("guarded /api/jobs answered without a session")
	}
}

func TestRequestBodyLimits(t *testing.T) {
	ts := newTestServer(t, nil)
	huge := `{"name":"` + strings.Repeat("x", maxJobBody) + `"}`
	if code, body := do(t, "POST", ts.URL+"/api/jobs", huge); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized create: %d %s", code, body)
	}
	if code, body := do(t, "PUT", ts.URL+"/api/jobs/x", huge); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized update: %d %s", code, body)
	}
	bigPreview := `{"yaml":"` + strings.Repeat("x", maxPreviewBody) + `"}`
	if code, body := do(t, "POST", ts.URL+"/api/preview", bigPreview); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized preview: %d %s", code, body)
	}
	if code, _ := do(t, "POST", ts.URL+"/api/jobs", `{bad json`); code != http.StatusBadRequest {
		t.Fatalf("bad json: %d", code)
	}
}

// A preview cannot be used to allocate unbounded memory through randHex.
func TestPreviewRandHexClamped(t *testing.T) {
	ts := newTestServer(t, nil)
	yaml := "name: t\nvendor: T\nformat: raw\nfacility: 16\nevents:\n  - weight: 1\n    severity: 6\n    template: \"{{randHex 1000000000}}\"\n"
	req, _ := json.Marshal(map[string]any{"yaml": yaml, "count": 1})
	code, body := do(t, "POST", ts.URL+"/api/preview", string(req))
	if code != 200 {
		t.Fatalf("preview: %d %s", code, body)
	}
	var out struct{ Samples []string }
	if err := json.Unmarshal(body, &out); err != nil || len(out.Samples) != 1 {
		t.Fatalf("preview body: %s", body)
	}
	if n := len(out.Samples[0]); n > 2048 {
		t.Fatalf("randHex not clamped: %d bytes", n)
	}
}

// Double-clicked Stop, Stop + Stop-all and Delete + Stop through the HTTP
// API: every request answers, and the API keeps working afterwards.
func TestConcurrentStopViaHTTP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	go func() {
		buf := make([]byte, 65536)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
	port := pc.LocalAddr().(*net.UDPAddr).Port
	ts := newTestServer(t, nil)

	for round := 0; round < 5; round++ {
		cfg := fmt.Sprintf(`{"name":"j%d","preset":"linux-host","host":"127.0.0.1","port":%d,"transport":"udp","rate":500,"facility":-1}`, round, port)
		code, body := do(t, "POST", ts.URL+"/api/jobs", cfg)
		if code != 201 {
			t.Fatalf("create: %d %s", code, body)
		}
		var st struct{ ID string }
		json.Unmarshal(body, &st)
		if code, body := do(t, "POST", ts.URL+"/api/jobs/"+st.ID+"/start", ""); code != 204 {
			t.Fatalf("start: %d %s", code, body)
		}

		var wg sync.WaitGroup
		for i := 0; i < 12; i++ {
			wg.Go(func() {
				switch {
				case i == 0 && round%2 == 0:
					if code, _ := do(t, "DELETE", ts.URL+"/api/jobs/"+st.ID, ""); code != 204 {
						t.Errorf("delete: %d", code)
					}
				case i%3 == 0:
					if code, _ := do(t, "POST", ts.URL+"/api/jobs/stop-all", ""); code != 204 {
						t.Errorf("stop-all: %d", code)
					}
				default:
					// 400 "job not found" is fine once a concurrent delete won
					if code, body := do(t, "POST", ts.URL+"/api/jobs/"+st.ID+"/stop", ""); code != 204 &&
						!strings.Contains(string(body), "not found") {
						t.Errorf("stop: %d %s", code, body)
					}
				}
			})
		}
		wg.Wait()

		code, body = do(t, "GET", ts.URL+"/api/jobs", "")
		if code != 200 {
			t.Fatalf("list after stops: %d", code)
		}
		var jobs []struct {
			Name    string
			Running bool
		}
		json.Unmarshal(body, &jobs)
		for _, j := range jobs {
			if j.Running {
				t.Fatalf("round %d: %s still running", round, j.Name)
			}
		}
	}
}
