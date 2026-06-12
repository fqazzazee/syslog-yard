package netclass

import (
	"net/netip"
	"testing"
)

func TestExtractKV(t *testing.T) {
	ips := Extract("fw-edge", `date=2026-06-12 srcip=192.168.1.50 dstip=203.0.113.9 action=accept`)
	if ips.Src.String() != "192.168.1.50" {
		t.Errorf("src = %v", ips.Src)
	}
	if ips.Dst.String() != "203.0.113.9" {
		t.Errorf("dst = %v", ips.Dst)
	}
	if len(ips.All) != 2 {
		t.Errorf("all = %v", ips.All)
	}
}

func TestExtractBareAndHost(t *testing.T) {
	ips := Extract("10.0.0.7", "Failed password for root from 198.51.100.23 port 4242 ssh2 at 12:30:01")
	want := map[string]bool{"198.51.100.23": true, "10.0.0.7": true}
	if len(ips.All) != len(want) {
		t.Fatalf("all = %v", ips.All)
	}
	for _, a := range ips.All {
		if !want[a.String()] {
			t.Errorf("unexpected %v", a)
		}
	}
	if ips.Src.IsValid() && ips.Src.String() != "198.51.100.23" {
		// "from=" needs an equals sign; bare "from " must not set Src.
		t.Errorf("src should be unset, got %v", ips.Src)
	}
}

func TestExtractIPv6(t *testing.T) {
	ips := Extract("h", "connection from 2001:db8::1 refused")
	if len(ips.All) != 1 || ips.All[0].String() != "2001:db8::1" {
		t.Errorf("all = %v", ips.All)
	}
}

func TestScope(t *testing.T) {
	cases := map[string]string{
		"10.1.2.3":      ScopeInternal,
		"172.20.0.9":    ScopeInternal,
		"192.168.0.1":   ScopeInternal,
		"fd00::5":       ScopeInternal,
		"127.0.0.1":     ScopeSpecial,
		"169.254.1.1":   ScopeSpecial,
		"100.64.0.8":    ScopeSpecial,
		"224.0.0.251":   ScopeSpecial,
		"8.8.8.8":       ScopeExternal,
		"2600:1900::1":  ScopeExternal,
		"203.0.113.250": ScopeSpecial, // TEST-NET-3
	}
	for ip, want := range cases {
		if got := Scope(netip.MustParseAddr(ip)); got != want {
			t.Errorf("Scope(%s) = %s, want %s", ip, got, want)
		}
	}
}

func TestSetContains(t *testing.T) {
	set := NewSet("malicious", []netip.Prefix{
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("41.77.240.0/22"),
		netip.MustParsePrefix("2001:db8:bad::/48"),
	})
	for _, in := range []string{"198.51.100.1", "198.51.100.255", "41.77.243.255", "2001:db8:bad::99"} {
		if !set.Contains(netip.MustParseAddr(in)) {
			t.Errorf("%s should match", in)
		}
	}
	for _, out := range []string{"198.51.101.0", "41.77.244.0", "2001:db8:bae::1", "8.8.8.8"} {
		if set.Contains(netip.MustParseAddr(out)) {
			t.Errorf("%s should not match", out)
		}
	}
}

func TestClassifyDirection(t *testing.T) {
	cases := []struct {
		msg  string
		want string
	}{
		{"srcip=10.0.0.5 dstip=8.8.8.8", DirOutbound},
		{"srcip=8.8.8.8 dstip=10.0.0.5", DirInbound},
		{"srcip=10.0.0.5 dstip=192.168.9.9", DirInternal},
		{"srcip=1.1.1.1 dstip=8.8.8.8", DirExternal},
		{"no addresses here", DirUnknown},
	}
	for _, c := range cases {
		got := Classify(Extract("h", c.msg), nil)
		if got.Direction != c.want {
			t.Errorf("%q → %s, want %s", c.msg, got.Direction, c.want)
		}
	}
}

func TestClassifyHits(t *testing.T) {
	bad := NewSet("malicious", []netip.Prefix{netip.MustParsePrefix("41.77.240.0/22")})
	res := Classify(Extract("h", "srcip=41.77.240.7 dstip=10.0.0.2 denied"), []*Set{bad})
	if res.Direction != DirInbound {
		t.Errorf("direction = %s", res.Direction)
	}
	if len(res.Hits["malicious"]) != 1 || res.Hits["malicious"][0] != "41.77.240.7" {
		t.Errorf("hits = %v", res.Hits)
	}
}
