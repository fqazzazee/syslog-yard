// Package tap receives the duplicate message stream syslog-ng writes to a
// unix datagram socket (one tap destination per source node) and fans it
// out to live-tail subscribers, keeping a small replay ring.
package tap

import (
	"context"
	"net"
	"os"
	"strings"
	"sync"
)

const (
	ringSize   = 200
	subBuffer  = 64
	maxPayload = 16 * 1024
)

// Event is one message seen on a wire. Src is the source node's ident.
type Event struct {
	Seq     int64  `json:"seq"`
	Src     string `json:"src"`
	Time    string `json:"time"`
	Host    string `json:"host"`
	Program string `json:"program"`
	Message string `json:"message"`
}

type Tap struct {
	mu   sync.Mutex
	seq  int64
	ring []Event
	subs map[chan Event]struct{}
}

func New() *Tap {
	return &Tap{subs: map[chan Event]struct{}{}}
}

// Listen binds the datagram socket (replacing a stale file) and consumes
// events until ctx is done.
func (t *Tap) Listen(ctx context.Context, path string) error {
	os.Remove(path)
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: path, Net: "unixgram"})
	if err != nil {
		return err
	}
	go func() {
		<-ctx.Done()
		conn.Close()
		os.Remove(path)
	}()
	go func() {
		buf := make([]byte, maxPayload)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return // closed on shutdown
			}
			t.publish(string(buf[:n]))
		}
	}()
	return nil
}

// publish parses the tab-separated tap template:
// src \t isodate \t host \t program \t message
func (t *Tap) publish(line string) {
	line = strings.TrimRight(line, "\n")
	parts := strings.SplitN(line, "\t", 5)
	if len(parts) < 5 {
		return
	}
	t.mu.Lock()
	t.seq++
	ev := Event{Seq: t.seq, Src: parts[0], Time: parts[1], Host: parts[2], Program: parts[3], Message: parts[4]}
	t.ring = append(t.ring, ev)
	if len(t.ring) > ringSize {
		t.ring = t.ring[len(t.ring)-ringSize:]
	}
	for ch := range t.subs {
		select {
		case ch <- ev:
		default: // slow subscriber: drop rather than block the reader
		}
	}
	t.mu.Unlock()
}

// Subscribe returns the replay ring and a channel of subsequent events;
// call the cancel func to unsubscribe.
func (t *Tap) Subscribe() ([]Event, chan Event, func()) {
	ch := make(chan Event, subBuffer)
	t.mu.Lock()
	replay := append([]Event(nil), t.ring...)
	t.subs[ch] = struct{}{}
	t.mu.Unlock()
	return replay, ch, func() {
		t.mu.Lock()
		delete(t.subs, ch)
		t.mu.Unlock()
	}
}
