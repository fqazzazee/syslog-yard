// Package ws is the live-tail hub: every connected client holds a
// condition from the shared AST, and each freshly inserted entry is fanned
// out to the clients whose condition matches — the WebSocket twin of the
// bucket's SQL query.
package ws

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/syslog-yard/syslog-bucket/internal/rules"
	"github.com/syslog-yard/syslog-bucket/internal/store"
)

const (
	clientBuffer = 256
	writeTimeout = 5 * time.Second
)

type client struct {
	cond              rules.Cond
	includeSuppressed bool
	ch                chan []byte
}

type Hub struct {
	mu      sync.RWMutex
	clients map[*client]struct{}
	origins []string // extra allowed Origin host patterns; same-origin always passes
}

func NewHub() *Hub {
	return &Hub{clients: make(map[*client]struct{})}
}

// SetOriginPatterns admits cross-origin live-tail handshakes from hosts
// matching these path.Match patterns (e.g. "localhost:5173"), on top of the
// same-origin requests that are always allowed. Empty patterns are ignored.
// Every allowed origin can read the live log stream with the user's cookie,
// so keep this to development setups (BUCKET_WS_ORIGINS).
func (h *Hub) SetOriginPatterns(patterns []string) {
	var keep []string
	for _, p := range patterns {
		if p = strings.TrimSpace(p); p != "" {
			keep = append(keep, p)
		}
	}
	h.mu.Lock()
	h.origins = keep
	h.mu.Unlock()
}

func (h *Hub) originPatterns() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.origins
}

// Broadcast pushes entries that just landed in the database to every
// matching subscriber. Slow clients lose frames rather than stalling ingest.
func (h *Hub) Broadcast(entries []store.Entry) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if len(h.clients) == 0 {
		return
	}
	for i := range entries {
		e := &entries[i]
		var frame []byte
		for c := range h.clients {
			if e.Suppressed && !c.includeSuppressed {
				continue
			}
			if !c.cond.Match(e) {
				continue
			}
			if frame == nil {
				var err error
				if frame, err = json.Marshal(map[string]any{"type": "entry", "entry": e}); err != nil {
					return
				}
			}
			select {
			case c.ch <- frame:
			default: // client buffer full; drop the frame
			}
		}
	}
}

// Serve upgrades the request and streams matching entries until the client
// disconnects. cond has already been validated by the API layer.
func (h *Hub) Serve(w http.ResponseWriter, r *http.Request, cond rules.Cond, includeSuppressed bool) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		// Same-origin only by default: the SPA (and the Vite dev proxy, which
		// keeps the Host header) always connects to its own host. Cookies are
		// scoped by host, not port, so a wildcard like "localhost:*" would let
		// any page served from another local port read the live stream.
		OriginPatterns: h.originPatterns(),
	})
	if err != nil {
		slog.Warn("ws: accept", "error", err)
		return
	}
	defer conn.CloseNow()

	c := &client{cond: cond, includeSuppressed: includeSuppressed, ch: make(chan []byte, clientBuffer)}
	h.mu.Lock()
	h.clients[c] = struct{}{}
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.clients, c)
		h.mu.Unlock()
	}()

	// We never expect client messages; CloseRead surfaces disconnects (and
	// handles pings) through ctx.
	ctx := conn.CloseRead(r.Context())
	for {
		select {
		case frame := <-c.ch:
			wctx, cancel := context.WithTimeout(ctx, writeTimeout)
			err := conn.Write(wctx, websocket.MessageText, frame)
			cancel()
			if err != nil {
				return
			}
		case <-ctx.Done():
			conn.Close(websocket.StatusNormalClosure, "")
			return
		}
	}
}
