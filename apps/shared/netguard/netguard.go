// Package netguard is the one outbound-connection guard for notification
// delivery (bucket webhook, Slack/Teams and SMTP channels; valve notify
// nodes). Whoever can configure a channel chooses where the server
// connects, so the guard keeps those connections off the host itself and
// off cloud metadata services:
//
//   - refused: loopback, unspecified (incl. 0.0.0.0/8), link-local
//     (incl. 169.254.169.254), multicast, and the metadata addresses
//     outside link-local (AWS IMDS over IPv6, Alibaba Cloud);
//   - allowed: everything else, RFC 1918 included — webhook sinks and mail
//     relays usually live on the same private network as the yard;
//   - HTTP redirects are never followed (a 3xx is reported as a failure).
//
// The check runs in the dialer's Control hook, after DNS resolution, on the
// address actually being connected to, so a name that resolves to a
// blocked address is refused with no gap between check and connect.
//
// Proxies: HTTP(S)_PROXY is ignored by default. Through a proxy the dial
// guard would only see the proxy's address and the proxy would happily
// fetch http://169.254.169.254/ for us, so proxied delivery is opt-in
// (YARD_NOTIFY_PROXY=true). With it, each target host is resolved here and
// refused if any address is blocked, before the request is handed to the
// proxy; the proxy itself must be at an allowed address too. That check is
// best effort — the proxy resolves the name again — and a target that does
// not resolve from the yard is refused rather than sent blind.
package netguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"syscall"
	"time"
)

// ErrBlocked is wrapped by every refusal.
var ErrBlocked = errors.New("destination address not allowed")

// ProxyEnv is the opt-in switch for proxied notification delivery.
const ProxyEnv = "YARD_NOTIFY_PROXY"

// metadataAddrs are cloud metadata endpoints outside the link-local range
// (169.254.169.254 and fe80::/10 are covered by the link-local rule).
var metadataAddrs = []netip.Addr{
	netip.MustParseAddr("fd00:ec2::254"),   // AWS IMDS over IPv6
	netip.MustParseAddr("100.100.100.200"), // Alibaba Cloud
}

// Guard is an outbound policy. The zero value is the production policy
// without proxy use; New reads the proxy opt-in from the environment.
type Guard struct {
	// AllowLoopback lets tests reach httptest servers on 127.0.0.1.
	AllowLoopback bool
	// UseProxy routes HTTP requests through HTTP(S)_PROXY (see the package
	// comment). Set from YARD_NOTIFY_PROXY by New.
	UseProxy bool

	// proxy picks the proxy for a request when UseProxy is set; nil means
	// http.ProxyFromEnvironment. A test hook: the stdlib caches the
	// environment on first use.
	proxy func(*http.Request) (*url.URL, error)
	// lookup resolves a target host when UseProxy is set; nil means
	// net.DefaultResolver.
	lookup func(ctx context.Context, host string) ([]netip.Addr, error)
}

// New returns the guard configured from the environment.
func New() *Guard {
	on, _ := strconv.ParseBool(os.Getenv(ProxyEnv))
	return &Guard{UseProxy: on}
}

// Reason answers why ip is refused, or "" when it is allowed.
func (g *Guard) Reason(ip netip.Addr) string {
	ip = ip.Unmap()
	switch {
	case ip.IsLoopback():
		if g.AllowLoopback {
			return ""
		}
		return "loopback"
	case ip.IsUnspecified(), ip.Is4() && ip.As4()[0] == 0:
		return "unspecified"
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		return "link-local"
	case ip.IsMulticast(), ip.IsInterfaceLocalMulticast():
		return "multicast"
	}
	for _, m := range metadataAddrs {
		if ip == m {
			return "cloud metadata"
		}
	}
	return ""
}

// Check refuses a blocked address with an error wrapping ErrBlocked.
func (g *Guard) Check(ip netip.Addr) error {
	if r := g.Reason(ip); r != "" {
		return fmt.Errorf("%w: %s address %s", ErrBlocked, r, ip.Unmap())
	}
	return nil
}

// control is the net.Dialer Control hook: address is the resolved IP:port.
func (g *Guard) control(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("%w: %q is not an IP address", ErrBlocked, host)
	}
	return g.Check(ip)
}

// Dialer returns a dialer that refuses blocked addresses (for SMTP and
// other non-HTTP deliveries).
func (g *Guard) Dialer(timeout time.Duration) *net.Dialer {
	return &net.Dialer{Timeout: timeout, Control: g.control}
}

// HTTPClient returns a client for webhook-style deliveries: guarded dialer,
// no redirects, no proxy unless UseProxy, timeout bounding the whole
// request.
func (g *Guard) HTTPClient(timeout time.Duration) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.DialContext = g.Dialer(timeout).DialContext
	tr.Proxy = nil
	if g.UseProxy {
		tr.Proxy = g.proxyFor
	}
	tr.TLSHandshakeTimeout = timeout
	tr.ResponseHeaderTimeout = timeout
	tr.MaxIdleConns = 16
	return &http.Client{
		Timeout:   timeout,
		Transport: tr,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// proxyFor picks the proxy and, when there is one, checks the target here,
// since the dial guard will only see the proxy's address.
func (g *Guard) proxyFor(req *http.Request) (*url.URL, error) {
	pick := g.proxy
	if pick == nil {
		pick = http.ProxyFromEnvironment
	}
	pu, err := pick(req)
	if err != nil || pu == nil {
		return pu, err // direct (e.g. NO_PROXY): the dial guard applies
	}
	if err := g.checkHost(req.Context(), req.URL.Hostname()); err != nil {
		return nil, err
	}
	return pu, nil
}

// checkHost refuses host when it is, or resolves to, a blocked address.
func (g *Guard) checkHost(ctx context.Context, host string) error {
	if ip, err := netip.ParseAddr(host); err == nil {
		return g.Check(ip)
	}
	lookup := g.lookup
	if lookup == nil {
		lookup = func(ctx context.Context, host string) ([]netip.Addr, error) {
			return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		}
	}
	addrs, err := lookup(ctx, host)
	if err != nil || len(addrs) == 0 {
		return fmt.Errorf("%w: cannot resolve %q to check it before proxying", ErrBlocked, host)
	}
	for _, a := range addrs {
		if err := g.Check(a); err != nil {
			return err
		}
	}
	return nil
}
