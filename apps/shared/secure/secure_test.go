package secure

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func ok(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }

type req struct {
	method, host, origin, site, ctype, body, remote, fwdHost string
}

func (c req) build() *http.Request {
	var r *http.Request
	if c.body != "" {
		r = httptest.NewRequest(c.method, "/api/x", strings.NewReader(c.body))
	} else {
		r = httptest.NewRequest(c.method, "/api/x", nil)
	}
	r.Host = c.host
	if c.origin != "" {
		r.Header.Set("Origin", c.origin)
	}
	if c.site != "" {
		r.Header.Set("Sec-Fetch-Site", c.site)
	}
	if c.ctype != "" {
		r.Header.Set("Content-Type", c.ctype)
	}
	if c.remote != "" {
		r.RemoteAddr = c.remote
	}
	if c.fwdHost != "" {
		r.Header.Set("X-Forwarded-Host", c.fwdHost)
	}
	return r
}

func TestGuard(t *testing.T) {
	const host = "localhost:8082"
	const js = "application/json"
	pol := &Policy{
		TrustedOrigins: []string{"https://yard.example.com"},
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	}
	h := pol.Guard(http.HandlerFunc(ok))

	cases := []struct {
		name string
		req
		want int
	}{
		// Safe methods are never checked.
		{"get cross-site", req{method: "GET", host: host, origin: "http://evil", site: "cross-site"}, 204},
		{"head", req{method: "HEAD", host: host, site: "cross-site"}, 204},

		// Non-browser clients: no Origin, no Sec-Fetch-Site.
		{"curl json", req{method: "POST", host: host, ctype: js, body: "{}"}, 204},
		{"curl json charset", req{method: "PUT", host: host, ctype: "application/json; charset=utf-8", body: "{}"}, 204},
		{"curl bodyless delete", req{method: "DELETE", host: host}, 204},
		{"curl bodyless post", req{method: "POST", host: host}, 204},
		{"curl text/plain", req{method: "POST", host: host, ctype: "text/plain", body: "{}"}, 415},
		{"curl no ctype body", req{method: "POST", host: host, body: "{}"}, 415},
		{"curl form", req{method: "POST", host: host, ctype: "application/x-www-form-urlencoded", body: "a=b"}, 415},

		// The SPA itself.
		{"spa json", req{method: "POST", host: host, origin: "http://localhost:8082", site: "same-origin", ctype: js, body: "{}"}, 204},
		{"spa text/plain", req{method: "PUT", host: host, origin: "http://localhost:8082", site: "same-origin", ctype: "text/plain;charset=UTF-8", body: "{}"}, 204},
		{"spa multipart", req{method: "POST", host: host, origin: "http://localhost:8082", ctype: "multipart/form-data; boundary=x", body: "--x--"}, 204},
		{"spa bodyless", req{method: "POST", host: host, origin: "http://localhost:8082", site: "same-origin"}, 204},
		{"site-only proof", req{method: "POST", host: host, site: "same-origin", ctype: "text/plain", body: "x"}, 204},
		{"https origin via tls proxy", req{method: "POST", host: "yard.lab", origin: "https://yard.lab", ctype: js, body: "{}"}, 204},
		{"default port host", req{method: "POST", host: "yard.lab:80", origin: "http://yard.lab", ctype: js, body: "{}"}, 204},
		{"case-insensitive host", req{method: "POST", host: "Yard.Lab:8082", origin: "http://yard.lab:8082", ctype: js, body: "{}"}, 204},

		// Attacks: another port on the same host is same-site, not same-origin.
		{"other port text/plain", req{method: "POST", host: host, origin: "http://localhost:3000", site: "same-site", ctype: "text/plain", body: "{}"}, 403},
		{"other port no fetch-metadata", req{method: "POST", host: host, origin: "http://localhost:3000", ctype: "text/plain", body: "{}"}, 403},
		{"other port bodyless", req{method: "DELETE", host: host, origin: "http://localhost:3000"}, 403},
		{"cross-site metadata only", req{method: "POST", host: host, site: "cross-site", ctype: js, body: "{}"}, 403},
		{"same-site metadata only", req{method: "POST", host: host, site: "same-site"}, 403},
		{"null origin", req{method: "POST", host: host, origin: "null", ctype: js, body: "{}"}, 403},
		{"garbage origin", req{method: "POST", host: host, origin: "localhost:8082", ctype: js, body: "{}"}, 403},
		{"other scheme origin", req{method: "POST", host: host, origin: "ftp://localhost:8082", ctype: js, body: "{}"}, 403},
		{"wrong port same name", req{method: "POST", host: "yard.lab:8082", origin: "https://yard.lab", ctype: js, body: "{}"}, 403},
		{"site none no proof", req{method: "POST", host: host, site: "none", ctype: "text/plain", body: "x"}, 415},

		// Explicitly trusted origin.
		{"trusted origin", req{method: "POST", host: "127.0.0.1:8082", origin: "https://yard.example.com", site: "same-site", ctype: "text/plain", body: "x"}, 204},
		{"trusted origin case", req{method: "POST", host: "127.0.0.1:8082", origin: "HTTPS://YARD.EXAMPLE.COM", ctype: js, body: "{}"}, 204},

		// X-Forwarded-Host only from trusted proxies.
		{"fwd host trusted proxy", req{method: "POST", host: "127.0.0.1:8082", origin: "https://ui.lab", remote: "10.1.2.3:5555", fwdHost: "ui.lab", ctype: js, body: "{}"}, 204},
		{"fwd host chain", req{method: "POST", host: "127.0.0.1:8082", origin: "https://ui.lab", remote: "10.1.2.3:5555", fwdHost: "ui.lab, inner", ctype: js, body: "{}"}, 204},
		{"fwd host untrusted peer", req{method: "POST", host: "127.0.0.1:8082", origin: "https://ui.lab", remote: "192.0.2.1:5555", fwdHost: "ui.lab", ctype: js, body: "{}"}, 403},
	}
	for _, c := range cases {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, c.req.build())
		if w.Code != c.want {
			t.Errorf("%s: got %d, want %d (%s)", c.name, w.Code, c.want, strings.TrimSpace(w.Body.String()))
		}
	}
}

func TestEmptyPolicyIgnoresForwardedHost(t *testing.T) {
	h := (&Policy{}).Guard(http.HandlerFunc(ok))
	r := req{method: "POST", host: "127.0.0.1:8082", origin: "https://ui.lab", remote: "10.1.2.3:5555",
		fwdHost: "ui.lab", ctype: "application/json", body: "{}"}.build()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403", w.Code)
	}
}

func TestHeadersSetsHardeningAndGuards(t *testing.T) {
	h := Headers(http.HandlerFunc(ok))
	w := httptest.NewRecorder()
	r := req{method: "POST", host: "localhost:8082", origin: "http://localhost:3000"}.build()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("cross-origin POST got %d, want 403", w.Code)
	}
	for _, k := range []string{"Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy"} {
		if w.Header().Get(k) == "" {
			t.Errorf("missing %s on rejection", k)
		}
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "/", nil))
	if w.Code != http.StatusNoContent || w.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatalf("GET got %d / %q", w.Code, w.Header().Get("X-Frame-Options"))
	}
}

func TestClientIP(t *testing.T) {
	trusted, _ := ParseTrustedProxies("10.0.0.0/8")
	pol := &Policy{TrustedProxies: trusted}
	cases := []struct{ remote, xff, want string }{
		{"192.0.2.1:4000", "", "192.0.2.1"},
		{"192.0.2.1:4000", "203.0.113.9", "192.0.2.1"}, // untrusted peer: XFF ignored
		{"10.0.0.2:4000", "", "10.0.0.2"},
		{"10.0.0.2:4000", "203.0.113.9", "203.0.113.9"},
		{"10.0.0.2:4000", "6.6.6.6, 203.0.113.9, 10.0.0.7", "203.0.113.9"}, // spoofed left hop skipped
		{"10.0.0.2:4000", "junk, 10.0.0.7", "10.0.0.7"},
		{"[::ffff:10.0.0.2]:4000", "203.0.113.9", "203.0.113.9"},
	}
	for _, c := range cases {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = c.remote
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := pol.ClientIP(r); got != c.want {
			t.Errorf("remote=%s xff=%q: got %s, want %s", c.remote, c.xff, got, c.want)
		}
	}
}

func TestParseTrustedProxies(t *testing.T) {
	got, rejected := ParseTrustedProxies("10.0.0.0/8, 192.0.2.7 ::1,bogus\t10.0.0.0/33 ::ffff:192.0.2.9,,")
	if len(got) != 4 {
		t.Fatalf("got %v", got)
	}
	if !got[1].Contains(netip.MustParseAddr("192.0.2.7")) || got[1].Bits() != 32 {
		t.Fatalf("single IP not a /32: %v", got[1])
	}
	if got[3] != netip.MustParsePrefix("192.0.2.9/32") {
		t.Fatalf("mapped address not unmapped: %v", got[3])
	}
	if len(rejected) != 2 || rejected[0] != "bogus" || rejected[1] != "10.0.0.0/33" {
		t.Fatalf("rejected = %q", rejected)
	}
	if got, rejected := ParseTrustedProxies(""); got != nil || rejected != nil {
		t.Fatalf("empty: %v %v", got, rejected)
	}
}
