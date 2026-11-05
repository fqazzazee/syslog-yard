package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/syslog-yard/syslog-valve/internal/codegen"
	"github.com/syslog-yard/syslog-valve/internal/graph"
	"github.com/syslog-yard/syslog-valve/internal/notify"
	"github.com/syslog-yard/syslog-valve/internal/rotate"
	"github.com/syslog-yard/syslog-valve/internal/supervisor"
)

// fakeSyslogNG mimics syslog-ng's CLI and reload log lines. A config with a
// source on port 5999 passes --syntax-only but fails at reload, like a
// port that is already bound.
const fakeSyslogNG = `#!/bin/sh
if [ "$1" = "--version" ]; then echo "syslog-ng 4 (4.8.1)"; exit 0; fi
if [ "$1" = "--syntax-only" ]; then exit 0; fi
conf="$5"
hup() {
  if grep -q 'port(5999)' "$conf"; then
    echo "[t] Error binding socket; error='Address already in use (98)'" >&2
    echo "[t] Error initializing new configuration, reverting to old config;" >&2
  fi
  echo "[t] Configuration reload finished;" >&2
}
trap hup HUP
trap 'exit 0' TERM
echo "[t] syslog-ng starting up" >&2
while :; do sleep 0.05; done
`

type env struct {
	t       *testing.T
	dataDir string
	sup     *supervisor.Supervisor
	rotator *rotate.Rotator
	nd      *notify.Dispatcher
	srv     *Server
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dataDir := t.TempDir()
	bin := filepath.Join(t.TempDir(), "syslog-ng")
	if err := os.WriteFile(bin, []byte(fakeSyslogNG), 0o755); err != nil {
		t.Fatal(err)
	}
	sup := supervisor.New(bin, filepath.Join(dataDir, "syslog-ng"))
	if err := os.MkdirAll(filepath.Join(dataDir, "syslog-ng"), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := sup.Start(ctx, codegen.Minimal(sup.Version())); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cancel(); sup.Shutdown() })
	deadline := time.Now().Add(5 * time.Second)
	for !slices.ContainsFunc(sup.Status().Log, func(l string) bool { return strings.Contains(l, "starting up") }) {
		if time.Now().After(deadline) {
			t.Fatal("fake syslog-ng did not start")
		}
		time.Sleep(20 * time.Millisecond)
	}
	e := &env{t: t, dataDir: dataDir, sup: sup}
	e.rotator = &rotate.Rotator{ConfPath: filepath.Join(dataDir, "logrotate.conf"), StatePath: filepath.Join(dataDir, "logrotate.state")}
	e.restart()
	return e
}

// restart builds a fresh Server (and dispatcher) over the same data dir,
// as a process restart would.
func (e *env) restart() {
	e.nd = notify.New()
	e.srv = New(e.sup, e.dataDir, nil, nil, nil, e.rotator, nil, e.nd, nil)
	e.srv.SetHTTPPort(8081)
}

func (e *env) do(method, path string, body []byte) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if len(body) > 0 {
		// secure.Headers rejects non-JSON bodies on state-changing requests.
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	e.srv.ServeHTTP(rec, req)
	return rec
}

func (e *env) mustOK(method, path string, body []byte) *httptest.ResponseRecorder {
	e.t.Helper()
	rec := e.do(method, path, body)
	if rec.Code != http.StatusOK {
		e.t.Fatalf("%s %s: %d %s", method, path, rec.Code, rec.Body)
	}
	return rec
}

func (e *env) read(name string) string {
	data, _ := os.ReadFile(filepath.Join(e.dataDir, name))
	return string(data)
}

func (e *env) history() []supervisor.HistoryEntry { return e.sup.History() }

func flow(cacheDir string, withNotify bool, port int) []byte {
	g := graph.Graph{
		Nodes: []graph.Node{
			{ID: "source-1", Type: graph.TypeSource, Name: "in", Config: graph.Config{Transport: "udp", Port: port}},
			{ID: "cache-1", Type: graph.TypeCache, Name: "keep", Config: graph.Config{Dir: cacheDir}},
		},
		Edges: []graph.Edge{{From: "source-1", To: "cache-1"}},
	}
	if withNotify {
		g.Nodes = append(g.Nodes, graph.Node{ID: "notify-1", Type: graph.TypeNotify, Name: "page",
			Config: graph.Config{NotifyKind: "webhook", URL: "http://10.9.9.9/hook"}})
		g.Edges = append(g.Edges, graph.Edge{From: "source-1", To: "notify-1"})
	}
	data, _ := json.Marshal(g)
	return data
}

func TestApplyAndRollbackStayCoherent(t *testing.T) {
	e := newEnv(t)
	v1 := flow("one", true, 6514)
	e.mustOK("PUT", "/api/graph", v1)
	e.mustOK("POST", "/api/apply", nil)
	if lr := e.read("logrotate.conf"); !strings.Contains(lr, "/data/cache/one/messages.log") {
		t.Fatalf("logrotate after v1:\n%s", lr)
	}
	if got := e.nd.Targets(); !slices.Equal(got, []string{"notify_1"}) {
		t.Fatalf("notify targets after v1 = %v", got)
	}

	e.mustOK("PUT", "/api/graph", flow("two", false, 6514))
	e.mustOK("POST", "/api/apply", nil)
	if lr := e.read("logrotate.conf"); !strings.Contains(lr, "/two/") || strings.Contains(lr, "/one/") {
		t.Fatalf("logrotate after v2:\n%s", lr)
	}
	if got := e.nd.Targets(); len(got) != 0 {
		t.Fatalf("notify targets after v2 = %v", got)
	}

	h := e.history()
	if len(h) != 2 {
		t.Fatalf("history = %d entries", len(h))
	}
	time.Sleep(2 * time.Millisecond) // history ids are millisecond timestamps
	e.mustOK("POST", "/api/rollback/"+h[1].ID, nil)

	// Everything derived from the applied graph follows the rollback.
	if got := e.read("graph.json"); got != string(v1) {
		t.Fatalf("graph.json after rollback = %s", got)
	}
	if lr := e.read("logrotate.conf"); !strings.Contains(lr, "/one/") || strings.Contains(lr, "/two/") {
		t.Fatalf("logrotate after rollback:\n%s", lr)
	}
	if got := e.nd.Targets(); !slices.Equal(got, []string{"notify_1"}) {
		t.Fatalf("notify targets after rollback = %v", got)
	}
	if conf := e.read("syslog-ng/current.conf"); !strings.Contains(conf, "/one/") {
		t.Fatalf("current.conf after rollback:\n%s", conf)
	}
	if n := len(e.history()); n != 3 {
		t.Fatalf("rollback should be recorded as a new history entry; history = %d", n)
	}
}

func TestApplyReportsRuntimeRejection(t *testing.T) {
	e := newEnv(t)
	e.mustOK("PUT", "/api/graph", flow("one", true, 6514))
	e.mustOK("POST", "/api/apply", nil)
	confBefore := e.read("syslog-ng/current.conf")
	lrBefore := e.read("logrotate.conf")

	e.mustOK("PUT", "/api/graph", flow("two", false, 5999))
	rec := e.do("POST", "/api/apply", nil)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("apply of a config syslog-ng refuses: %d %s", rec.Code, rec.Body)
	}
	var body map[string]string
	json.Unmarshal(rec.Body.Bytes(), &body)
	if !strings.Contains(body["error"], "kept the previous one") || !strings.Contains(body["error"], "Address already in use") {
		t.Fatalf("error = %q", body["error"])
	}
	if e.read("syslog-ng/current.conf") != confBefore {
		t.Fatal("current.conf not restored after a refused reload")
	}
	if e.read("logrotate.conf") != lrBefore {
		t.Fatal("logrotate.conf changed by a refused apply")
	}
	if got := e.nd.Targets(); !slices.Equal(got, []string{"notify_1"}) {
		t.Fatalf("notify targets changed by a refused apply: %v", got)
	}
	if len(e.history()) != 1 {
		t.Fatal("refused config archived in history")
	}
}

func TestPutGraphRejectsHostileInput(t *testing.T) {
	e := newEnv(t)
	good := flow("one", false, 6514)
	e.mustOK("PUT", "/api/graph", good)

	var g graph.Graph
	json.Unmarshal(good, &g)
	g.Nodes[0].Name = "x\n};\ndestination d { program(\"id\"); };\n#"
	bad, _ := json.Marshal(g)
	if rec := e.do("PUT", "/api/graph", bad); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("newline in name: %d %s", rec.Code, rec.Body)
	}

	json.Unmarshal(good, &g)
	g.Nodes[1].Config.Dir = "x\n    postrotate\n        id\n    endscript"
	bad, _ = json.Marshal(g)
	if rec := e.do("PUT", "/api/graph", bad); rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("newline in dir: %d %s", rec.Code, rec.Body)
	}

	// A source on the valve's own HTTP port.
	json.Unmarshal(good, &g)
	g.Nodes[0].Config.Transport, g.Nodes[0].Config.Port = "tcp", 8081
	bad, _ = json.Marshal(g)
	if rec := e.do("PUT", "/api/graph", bad); rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "web UI") {
		t.Fatalf("source on the UI port: %d %s", rec.Code, rec.Body)
	}

	if e.read("graph.json") != string(good) {
		t.Fatal("rejected graph overwrote the saved one")
	}

	big := bytes.Repeat([]byte(" "), maxGraphBody+1)
	if rec := e.do("PUT", "/api/graph", big); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body: %d", rec.Code)
	}
}

// #63: every mutating route answers an oversized body with 413 and a JSON
// error, whether or not it reads a body, and whatever its declared length.
func TestBodyLimitsOnEveryMutatingRoute(t *testing.T) {
	e := newEnv(t)
	small := bytes.Repeat([]byte(" "), 64<<10+1)
	for _, path := range []string{"/api/notify/test", "/api/apply", "/api/rotate", "/api/certs/selfsigned", "/api/rollback/1"} {
		rec := e.do("POST", path, small)
		if rec.Code != http.StatusRequestEntityTooLarge || !strings.Contains(rec.Body.String(), `"error"`) {
			t.Errorf("POST %s: %d %s", path, rec.Code, rec.Body)
		}
	}
	// a body of unknown length is cut off while it is read
	req := httptest.NewRequest("PUT", "/api/graph", bytes.NewReader(bytes.Repeat([]byte(" "), maxGraphBody+1)))
	req.ContentLength = -1
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge || !strings.Contains(rec.Body.String(), `"error"`) {
		t.Fatalf("chunked oversized graph: %d %s", rec.Code, rec.Body)
	}
}

func TestStartupResyncsFromActiveGraph(t *testing.T) {
	e := newEnv(t)
	e.mustOK("PUT", "/api/graph", flow("one", true, 6514))
	e.mustOK("POST", "/api/apply", nil)

	// Simulate files left by an older version: a stale logrotate.conf, and
	// an archived graph whose name holds a line break (no longer accepted
	// on save, but must not stop a restart).
	os.WriteFile(e.rotator.ConfPath, []byte("stale\n"), 0o644)
	id := e.history()[0].ID
	gpath := filepath.Join(e.dataDir, "syslog-ng", "history", id+".graph.json")
	var g graph.Graph
	data, _ := os.ReadFile(gpath)
	json.Unmarshal(data, &g)
	g.Nodes[1].Name = "keep\nme"
	data, _ = json.Marshal(g)
	os.WriteFile(gpath, data, 0o644)

	e.restart()
	if lr := e.read("logrotate.conf"); !strings.Contains(lr, "# cache keep me\n") || !strings.Contains(lr, "/one/") {
		t.Fatalf("logrotate.conf not regenerated at startup:\n%s", lr)
	}
	if got := e.nd.Targets(); !slices.Equal(got, []string{"notify_1"}) {
		t.Fatalf("notify targets after restart = %v", got)
	}
}

func TestNotifyTestEndpoint(t *testing.T) {
	e := newEnv(t)
	for _, c := range []struct {
		body string
		code int
		want string
	}{
		{`{"kind":"email","url":"http://10.0.0.1/"}`, http.StatusBadRequest, "kind"},
		{`{"kind":"webhook","url":"file:///etc/passwd"}`, http.StatusBadRequest, "http"},
		{`{"kind":"webhook","url":"http://127.0.0.1:1/"}`, http.StatusBadGateway, "loopback"},
		{`{"kind":"slack","url":"http://169.254.169.254/latest/meta-data/"}`, http.StatusBadGateway, "link-local"},
	} {
		rec := e.do("POST", "/api/notify/test", []byte(c.body))
		if rec.Code != c.code || !strings.Contains(rec.Body.String(), c.want) {
			t.Errorf("%s: %d %s", c.body, rec.Code, rec.Body)
		}
	}
}
