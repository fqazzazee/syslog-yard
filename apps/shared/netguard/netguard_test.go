package netguard

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestReason(t *testing.T) {
	g := &Guard{}
	for addr, blocked := range map[string]bool{
		"127.0.0.1": true, "127.5.6.7": true, "::1": true, "::ffff:127.0.0.1": true,
		"0.0.0.0": true, "0.1.2.3": true, "::": true,
		"169.254.169.254": true, "169.254.1.1": true, "fe80::1": true,
		"224.0.0.1": true, "239.1.2.3": true, "ff02::1": true, "ff01::1": true,
		"fd00:ec2::254": true, "100.100.100.200": true, "::ffff:169.254.169.254": true,
		"10.0.0.5": false, "172.18.0.4": false, "192.168.1.10": false,
		"8.8.8.8": false, "203.0.113.7": false, "fd00::5": false, "2001:db8::1": false,
		"100.100.100.201": false,
	} {
		ip := netip.MustParseAddr(addr)
		if got := g.Reason(ip) != ""; got != blocked {
			t.Errorf("%s: blocked=%v, want %v", addr, got, blocked)
		}
		if err := g.Check(ip); (err != nil) != blocked || (err != nil && !errors.Is(err, ErrBlocked)) {
			t.Errorf("%s: Check = %v", addr, err)
		}
	}
	g.AllowLoopback = true
	if g.Reason(netip.MustParseAddr("127.0.0.1")) != "" {
		t.Error("AllowLoopback did not allow loopback")
	}
	if g.Reason(netip.MustParseAddr("169.254.169.254")) == "" {
		t.Error("AllowLoopback must not open link-local")
	}
}

func TestHTTPClientRefusesLoopback(t *testing.T) {
	var hit atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit.Store(true) }))
	defer srv.Close()
	_, err := (&Guard{}).HTTPClient(2*time.Second).Post(srv.URL, "text/plain", nil)
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("err = %v, want ErrBlocked", err)
	}
	if hit.Load() {
		t.Error("loopback endpoint reached")
	}
}

// A name that resolves to a blocked address is refused at dial time.
func TestDialerChecksResolvedAddress(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	_, err = (&Guard{}).Dialer(time.Second).DialContext(context.Background(), "tcp", net.JoinHostPort("localhost", port))
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("err = %v, want ErrBlocked", err)
	}
}

func TestHTTPClientNoRedirects(t *testing.T) {
	var followed atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { followed.Store(true) }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer srv.Close()
	resp, err := (&Guard{AllowLoopback: true}).HTTPClient(2*time.Second).Post(srv.URL, "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || followed.Load() {
		t.Errorf("status %d, followed=%v", resp.StatusCode, followed.Load())
	}
}

// fakeProxy records the requests a forward proxy receives and answers 204.
func fakeProxy(t *testing.T) (*httptest.Server, *atomic.Int32) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(srv.Close)
	return srv, &n
}

func TestProxyIgnoredByDefault(t *testing.T) {
	t.Setenv(ProxyEnv, "")
	t.Setenv("HTTP_PROXY", "http://192.0.2.1:3128")
	g := New()
	if g.UseProxy {
		t.Fatal("proxy use must be opt-in")
	}
	tr := g.HTTPClient(time.Second).Transport.(*http.Transport)
	if tr.Proxy != nil {
		t.Error("transport consults the proxy environment without the opt-in")
	}
	t.Setenv(ProxyEnv, "true")
	if !New().UseProxy {
		t.Errorf("%s=true not honoured", ProxyEnv)
	}
}

func TestProxiedTargetIsChecked(t *testing.T) {
	proxy, hits := fakeProxy(t)
	pu, _ := url.Parse(proxy.URL)
	g := &Guard{UseProxy: true, AllowLoopback: true, proxy: http.ProxyURL(pu)}
	// The test proxy lives on loopback, so loopback is allowed here; the
	// target checks below must still refuse metadata and link-local.
	client := g.HTTPClient(2 * time.Second)

	for _, target := range []string{"http://169.254.169.254/latest/meta-data/", "http://[fd00:ec2::254]/", "http://0.0.0.0/"} {
		_, err := client.Post(target, "text/plain", nil)
		if !errors.Is(err, ErrBlocked) {
			t.Errorf("%s: err = %v, want ErrBlocked", target, err)
		}
	}

	g.lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("203.0.113.9"), netip.MustParseAddr("169.254.169.254")}, nil
	}
	if _, err := client.Post("http://rebind.example/", "text/plain", nil); !errors.Is(err, ErrBlocked) {
		t.Errorf("name with one blocked address: err = %v", err)
	}
	g.lookup = func(context.Context, string) ([]netip.Addr, error) { return nil, errors.New("no such host") }
	if _, err := client.Post("http://unresolvable.example/", "text/plain", nil); !errors.Is(err, ErrBlocked) {
		t.Errorf("unresolvable name: err = %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("proxy received %d refused requests", hits.Load())
	}

	g.lookup = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("203.0.113.9")}, nil
	}
	resp, err := client.Post("http://hooks.example/x", "text/plain", strings.NewReader("hi"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if hits.Load() != 1 {
		t.Errorf("allowed target did not go through the proxy (hits=%d)", hits.Load())
	}
}

// The proxy's own address is dial-guarded like any other.
func TestProxyAddressIsGuarded(t *testing.T) {
	proxy, hits := fakeProxy(t)
	pu, _ := url.Parse(proxy.URL)
	g := &Guard{UseProxy: true, proxy: http.ProxyURL(pu),
		lookup: func(context.Context, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("203.0.113.9")}, nil
		}}
	_, err := g.HTTPClient(2*time.Second).Post("http://hooks.example/", "text/plain", nil)
	if !errors.Is(err, ErrBlocked) || hits.Load() != 0 {
		t.Errorf("loopback proxy: err = %v, hits = %d", err, hits.Load())
	}
}
