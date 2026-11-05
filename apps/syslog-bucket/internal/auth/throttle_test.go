package auth

import (
	"fmt"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestThrottleLocksAfterMaxFails(t *testing.T) {
	tr := newThrottle(3, time.Minute)
	const key = "admin"

	for i := 0; i < 2; i++ {
		if ok, _ := tr.allow(key); !ok {
			t.Fatalf("attempt %d should be allowed", i)
		}
		tr.fail(key)
	}
	// Third failure trips the lock.
	if ok, _ := tr.allow(key); !ok {
		t.Fatal("third attempt should still be allowed before its failure")
	}
	tr.fail(key)
	ok, retry := tr.allow(key)
	if ok {
		t.Fatal("account should be locked after max failures")
	}
	if retry <= 0 || retry > time.Minute {
		t.Fatalf("unexpected retry-after: %v", retry)
	}
}

func TestThrottleResetOnSuccess(t *testing.T) {
	tr := newThrottle(3, time.Minute)
	const key = "alice"
	tr.fail(key)
	tr.fail(key)
	tr.reset(key) // a correct password clears the count
	tr.fail(key)
	if ok, _ := tr.allow(key); !ok {
		t.Fatal("reset should have cleared earlier failures")
	}
}

func TestGuardLocksSourceNotAccount(t *testing.T) {
	g := newGuard()
	for i := 0; i < loginMaxFails; i++ {
		g.fail("admin", "203.0.113.9")
	}
	if ok, _ := g.allow("admin", "203.0.113.9"); ok {
		t.Fatal("the guessing source should be locked out")
	}
	if ok, _ := g.allow("admin", "198.51.100.7"); !ok {
		t.Fatal("the real admin from another address must still be able to sign in")
	}
}

func TestGuardAccountCeiling(t *testing.T) {
	g := newGuard()
	// A brute force spread over many addresses, each staying under the
	// per-source limit, still trips the per-account ceiling.
	for i := 0; i < accountMaxFails; i++ {
		g.fail("admin", fmt.Sprintf("10.0.%d.%d", i/(loginMaxFails-1), i%(loginMaxFails-1)))
	}
	if ok, retry := g.allow("admin", "192.0.2.1"); ok || retry <= 0 {
		t.Fatalf("account should be locked after %d distributed failures", accountMaxFails)
	}
	if ok, _ := g.allow("alice", "192.0.2.1"); !ok {
		t.Fatal("other accounts are unaffected")
	}
	g.succeed("admin", "192.0.2.1")
	if ok, _ := g.allow("admin", "192.0.2.1"); !ok {
		t.Fatal("success clears the account counter")
	}
}

func TestGuardSingleSourceCannotTripCeiling(t *testing.T) {
	// One source gets at most loginMaxFails tries per lockout cycle, so within
	// one account window it must stay well below the account ceiling —
	// otherwise a single attacker could lock the account for everyone again.
	cycles := int(accountWindow/loginWindow) + 1
	if perSource := cycles * loginMaxFails; perSource*2 > accountMaxFails {
		t.Fatalf("one source can make %d attempts per %v; ceiling %d leaves too little headroom",
			perSource, accountWindow, accountMaxFails)
	}
}

func TestFixedThrottleWindowExpires(t *testing.T) {
	tr := newFixedThrottle(3, time.Minute)
	tr.fail("k")
	tr.fail("k")
	tr.entries["k"].start = time.Now().Add(-2 * time.Minute) // window over
	tr.fail("k")
	if ok, _ := tr.allow("k"); !ok {
		t.Fatal("failures from an expired fixed window must not count")
	}
	if tr.entries["k"].count != 1 {
		t.Fatalf("count = %d, want 1 after window reset", tr.entries["k"].count)
	}
}

func TestClientIP(t *testing.T) {
	trusted, err := ParseTrustedProxies("10.0.0.0/8, 192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, remote, xff string
		trusted           []netip.Prefix
		want              string
	}{
		{"no proxies: peer wins", "203.0.113.5:4000", "1.2.3.4", nil, "203.0.113.5"},
		{"untrusted peer: header ignored", "203.0.113.5:4000", "1.2.3.4", trusted, "203.0.113.5"},
		{"trusted peer: client from header", "10.1.2.3:4000", "198.51.100.8", trusted, "198.51.100.8"},
		{"trusted peer: left-most entry wins", "10.1.2.3:4000", "198.51.100.8, 192.0.2.1", trusted, "198.51.100.8"},
		{"trusted peer, no header", "10.1.2.3:4000", "", trusted, "10.1.2.3"},
		{"trusted peer, malformed header", "10.1.2.3:4000", "junk, 198.51.100.8", trusted, "10.1.2.3"},
		{"ipv4-mapped peer", "[::ffff:203.0.113.5]:4000", "", nil, "203.0.113.5"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("POST", "/api/auth/login", nil)
		r.RemoteAddr = c.remote
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := clientIP(r, c.trusted); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
	if _, err := ParseTrustedProxies("10.0.0.0/33"); err == nil {
		t.Error("invalid CIDR should be rejected")
	}
	if _, err := ParseTrustedProxies("not-an-ip"); err == nil {
		t.Error("invalid IP should be rejected")
	}
}

func TestThrottleIsolatesKeys(t *testing.T) {
	tr := newThrottle(2, time.Minute)
	tr.fail("victim")
	tr.fail("victim") // locks "victim"
	if ok, _ := tr.allow("victim"); ok {
		t.Fatal("victim should be locked")
	}
	if ok, _ := tr.allow("bystander"); !ok {
		t.Fatal("an unrelated account must not be affected")
	}
}
