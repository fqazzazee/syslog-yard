package ws

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/syslog-yard/syslog-bucket/internal/rules"
)

// dial opens the live tail with the given Origin header and reports the
// handshake's HTTP status (101 on success).
func dial(t *testing.T, srv *httptest.Server, origin string) int {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	h := http.Header{}
	if origin != "" {
		h.Set("Origin", origin)
	}
	conn, resp, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), &websocket.DialOptions{HTTPHeader: h})
	if err == nil {
		conn.CloseNow()
	}
	if resp == nil {
		t.Fatalf("dial %q: no response: %v", origin, err)
	}
	return resp.StatusCode
}

func TestServeOriginCheck(t *testing.T) {
	hub := NewHub()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hub.Serve(w, r, rules.Cond{}, false)
	}))
	defer srv.Close()
	self := srv.URL // http://127.0.0.1:<port>

	if got := dial(t, srv, self); got != http.StatusSwitchingProtocols {
		t.Errorf("same origin: got %d, want 101", got)
	}
	if got := dial(t, srv, ""); got != http.StatusSwitchingProtocols {
		t.Errorf("no Origin (non-browser client): got %d, want 101", got)
	}
	for _, o := range []string{"http://127.0.0.1:1", "http://localhost:5173", "https://evil.example"} {
		if got := dial(t, srv, o); got != http.StatusForbidden {
			t.Errorf("cross origin %s: got %d, want 403", o, got)
		}
	}

	hub.SetOriginPatterns([]string{" localhost:5173 ", ""})
	if got := dial(t, srv, "http://localhost:5173"); got != http.StatusSwitchingProtocols {
		t.Errorf("configured origin: got %d, want 101", got)
	}
	if got := dial(t, srv, "http://localhost:3000"); got != http.StatusForbidden {
		t.Errorf("unlisted origin: got %d, want 403", got)
	}
}
