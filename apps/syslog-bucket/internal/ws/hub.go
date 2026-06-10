// Package ws is the live-tail hub (PLAN §9): every connected client holds a
// condition from the shared AST, and each freshly inserted entry is fanned
// out to the clients whose condition matches — the WebSocket twin of the
// bucket's SQL query.
package ws

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
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
}

func NewHub() *Hub {
	return &Hub{clients: make(map[*client]struct{})}
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
		// The SPA is same-origin in production; the patterns admit the Vite
		// dev server proxy.
		OriginPatterns: []string{"localhost:*", "127.0.0.1:*"},
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
