package engine

import (
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/syslog-yard/syslog-hose/internal/preset"
)

func TestFrame(t *testing.T) {
	got := Frame("<134>hello")
	if got != "10 <134>hello" {
		t.Fatalf("octet framing wrong: %q", got)
	}
}

// End to end: create a job against a local UDP listener, run ~1s at 200 EPS,
// verify messages arrive, are PRI-prefixed, and the rate is in the ballpark.
func TestJobSendsUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	port := pc.LocalAddr().(*net.UDPAddr).Port

	received := make(chan string, 1000)
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		buf := make([]byte, 65536)
		for {
			n, _, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			received <- string(buf[:n])
		}
	}()

	store, err := preset.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mgr, err := NewManager(store, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	st, err := mgr.Create(JobConfig{
		Name: "test", Preset: "cisco-asa", Host: "127.0.0.1", Port: port,
		Transport: "udp", Rate: 200, Facility: -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.Start(st.ID); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	if err := mgr.Stop(st.ID); err != nil {
		t.Fatal(err)
	}

	// let the reader drain in-flight datagrams, then stop it before closing
	// the channel it sends on
	time.Sleep(100 * time.Millisecond)
	pc.Close()
	<-readerDone
	close(received)
	count := 0
	for msg := range received {
		if !strings.HasPrefix(msg, "<16") { // facility 20 → PRI 160..167
			t.Fatalf("unexpected message: %q", msg)
		}
		if !strings.Contains(msg, "%ASA-") {
			t.Fatalf("not an ASA-shaped message: %q", msg)
		}
		count++
	}
	if count < 120 || count > 280 {
		t.Fatalf("expected ~200-220 events in ~1.1s, got %d", count)
	}

	// tail buffer captured events too
	if len(mgr.TailSince(0)) == 0 {
		t.Fatal("tail buffer empty")
	}
	// stats survived the run
	jobs := mgr.List()
	if len(jobs) != 1 || jobs[0].Sent != int64(count) {
		t.Fatalf("stats mismatch: listed %d jobs, sent=%d, received=%d", len(jobs), jobs[0].Sent, count)
	}
}

// TCP path with octet-counting framing must reassemble cleanly.
func TestJobSendsTCPFramed(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port

	got := make(chan string, 500)
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 0, 65536)
		tmp := make([]byte, 4096)
		for {
			n, err := conn.Read(tmp)
			if n > 0 {
				buf = append(buf, tmp[:n]...)
				for {
					sp := strings.IndexByte(string(buf), ' ')
					if sp < 0 {
						break
					}
					msgLen, err := strconv.Atoi(string(buf[:sp]))
					if err != nil {
						return
					}
					if len(buf) < sp+1+msgLen {
						break
					}
					got <- string(buf[sp+1 : sp+1+msgLen])
					buf = buf[sp+1+msgLen:]
				}
			}
			if err != nil {
				return
			}
		}
	}()

	store, _ := preset.NewStore(t.TempDir())
	mgr, _ := NewManager(store, t.TempDir())
	st, err := mgr.Create(JobConfig{
		Name: "tcp-test", Preset: "generic-rfc5424", Host: "127.0.0.1", Port: port,
		Transport: "tcp", Rate: 50, MaxEvents: 20, Facility: -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := mgr.Start(st.ID); err != nil {
		t.Fatal(err)
	}

	deadline := time.After(5 * time.Second)
	count := 0
	for count < 20 {
		select {
		case msg := <-got:
			if !strings.HasPrefix(msg, "<13") || !strings.Contains(msg, ">1 ") {
				t.Fatalf("bad RFC5424 frame: %q", msg)
			}
			count++
		case <-deadline:
			t.Fatalf("timed out, only %d/20 framed messages", count)
		}
	}
	mgr.Stop(st.ID)
}

// Persistence: jobs written to jobs.json come back on a fresh manager.
func TestJobPersistence(t *testing.T) {
	dir := t.TempDir()
	store, _ := preset.NewStore(t.TempDir())
	mgr, _ := NewManager(store, dir)
	st, err := mgr.Create(JobConfig{
		Name: "persisted", Preset: "linux-host", Host: "127.0.0.1", Port: 5514,
		Transport: "udp", Rate: 1, Facility: -1,
	})
	if err != nil {
		t.Fatal(err)
	}
	mgr2, err := NewManager(store, dir)
	if err != nil {
		t.Fatal(err)
	}
	jobs := mgr2.List()
	if len(jobs) != 1 || jobs[0].ID != st.ID || jobs[0].Name != "persisted" {
		t.Fatalf("persisted job not reloaded: %+v", jobs)
	}
}
