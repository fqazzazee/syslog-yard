package engine

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func udpTarget(t *testing.T) *net.UDPConn {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	return pc
}

func expectDatagram(t *testing.T, pc *net.UDPConn, want string) *net.UDPAddr {
	t.Helper()
	buf := make([]byte, 128)
	pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, from, err := pc.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("waiting for %q: %v", want, err)
	}
	if got := string(buf[:n]); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	return from
}

// fakeResolver stands in for DNS: it dials whatever target currently holds.
func fakeResolver(target *string, lookupErr *error) func(context.Context, string) (net.Conn, error) {
	return func(ctx context.Context, _ string) (net.Conn, error) {
		if *lookupErr != nil {
			return nil, *lookupErr
		}
		return dialUDP(ctx, *target)
	}
}

func TestUDPSenderFollowsAddressChange(t *testing.T) {
	a, b := udpTarget(t), udpTarget(t)
	target, lookupErr := a.LocalAddr().String(), error(nil)
	u := &udpSender{ctx: context.Background(), addr: "valve:514", dial: fakeResolver(&target, &lookupErr)}
	defer u.Close()

	if err := u.Send("one"); err != nil {
		t.Fatal(err)
	}
	expectDatagram(t, a, "one")

	target = b.LocalAddr().String()
	u.dialedAt = time.Now().Add(-udpRefresh)
	if err := u.Send("two"); err != nil {
		t.Fatal(err)
	}
	expectDatagram(t, b, "two")
}

func TestUDPSenderKeepsSocketWhenRefreshFailsOrAddressIsSame(t *testing.T) {
	a := udpTarget(t)
	target, lookupErr := a.LocalAddr().String(), error(nil)
	u := &udpSender{ctx: context.Background(), addr: "valve:514", dial: fakeResolver(&target, &lookupErr)}
	defer u.Close()

	if err := u.Send("one"); err != nil {
		t.Fatal(err)
	}
	first := expectDatagram(t, a, "one")

	u.dialedAt = time.Now().Add(-udpRefresh)
	if err := u.Send("same"); err != nil {
		t.Fatal(err)
	}
	if from := expectDatagram(t, a, "same"); from.Port != first.Port {
		t.Fatalf("source port changed from %d to %d with no address change", first.Port, from.Port)
	}

	lookupErr = errors.New("lookup failed")
	u.dialedAt = time.Now().Add(-udpRefresh)
	if err := u.Send("during outage"); err != nil {
		t.Fatalf("a failed refresh must keep the working socket: %v", err)
	}
	expectDatagram(t, a, "during outage")
}

func TestUDPSenderRetriesFailedFirstLookup(t *testing.T) {
	a := udpTarget(t)
	target, lookupErr := a.LocalAddr().String(), errors.New("no such host")
	calls := 0
	resolve := fakeResolver(&target, &lookupErr)
	u := &udpSender{ctx: context.Background(), addr: "valve:514", dial: func(ctx context.Context, addr string) (net.Conn, error) {
		calls++
		return resolve(ctx, addr)
	}}
	defer u.Close()

	if err := u.Send("early"); err == nil {
		t.Fatal("send without a resolved destination succeeded")
	}
	if err := u.Send("early"); err == nil {
		t.Fatal("send during the retry gap succeeded")
	}
	if calls != 1 {
		t.Fatalf("%d lookups during the retry gap, want 1", calls)
	}

	lookupErr = nil
	u.dialedAt = time.Now().Add(-udpRedialMin)
	if err := u.Send("late"); err != nil {
		t.Fatal(err)
	}
	expectDatagram(t, a, "late")
}

// A receiver that went away is reported by the next write; the sender then
// looks the name up again and delivers to the replacement.
func TestUDPSenderRedialsOnWriteError(t *testing.T) {
	gone := udpTarget(t)
	b := udpTarget(t)
	target, lookupErr := gone.LocalAddr().String(), error(nil)
	u := &udpSender{ctx: context.Background(), addr: "valve:514", dial: fakeResolver(&target, &lookupErr)}
	defer u.Close()

	if err := u.Send("one"); err != nil {
		t.Fatal(err)
	}
	gone.Close()
	if err := u.Send("lost"); err != nil { // draws the ICMP refusal
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)

	target = b.LocalAddr().String()
	u.dialedAt = time.Now().Add(-udpRedialMin)
	if err := u.Send("after"); err != nil {
		t.Fatal(err)
	}
	expectDatagram(t, b, "after")
}

func TestUDPSenderCloseBeforeFirstSend(t *testing.T) {
	s, err := NewSender(context.Background(), "udp", "127.0.0.1", 9, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}
