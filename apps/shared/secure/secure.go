// Package secure carries the hardening every yard UI serves: baseline
// response headers plus a cross-origin guard on state-changing requests.
// One body instead of a per-app copy: the suite's security posture is
// deliberately identical across hose, valve and bucket.
package secure

import (
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
)

// contentSecurityPolicy for the embedded SPAs. Scripts are external,
// content-hashed bundles ('self'); inline styles are needed for React
// style props and runtime-injected stylesheets; connect-src 'self' covers
// the same-origin REST API plus the live-tail WebSocket. frame-ancestors
// 'none' blocks clickjacking of the login form. No third-party origins:
// the UIs ship self-contained.
const contentSecurityPolicy = "default-src 'self'; " +
	"script-src 'self'; " +
	"style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; " +
	"font-src 'self' data:; " +
	"connect-src 'self'; " +
	"base-uri 'self'; " +
	"form-action 'self'; " +
	"frame-ancestors 'none'; " +
	"object-src 'none'"

// Headers adds baseline hardening headers to every response and runs the
// cross-origin guard (see Policy) configured from the environment. HSTS is
// deliberately omitted: it only helps over HTTPS and would wedge the
// http-on-localhost lab flow — enable it at the reverse proxy in
// production (see docs/SECURITY.md).
func Headers(next http.Handler) http.Handler {
	return headers(envPolicy().Guard(next))
}

func headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

// Policy is the cross-origin (CSRF) guard. The session cookie is
// SameSite=Lax, but every localhost:<port> — and every port of one lab
// host — is the same *site*, so a page served by any other tool on that
// host could otherwise POST to a yard API with the user's cookie. For
// POST/PUT/PATCH/DELETE the guard therefore:
//
//   - rejects Sec-Fetch-Site "cross-site" and "same-site";
//   - requires a present Origin to name this host (scheme-agnostic, so a
//     TLS-terminating proxy that preserves Host works);
//   - requires a body that is not JSON (text/plain, form or multipart —
//     the content types a browser can send cross-origin without a CORS
//     preflight) to carry positive same-origin proof: Sec-Fetch-Site
//     "same-origin" or a matching Origin.
//
// Requests with neither Origin nor Sec-Fetch-Site (curl, yardctl, the
// yardauth proxy) pass when bodyless or JSON: a browser cannot send those
// cross-origin without either header or a preflight the yard never grants.
type Policy struct {
	// TrustedOrigins are extra Origins (scheme://host[:port]) accepted
	// verbatim — e.g. the public name of a reverse proxy that rewrites
	// Host. Matching is case-insensitive.
	TrustedOrigins []string
	// TrustedProxies are the peers (by RemoteAddr) whose X-Forwarded-Host
	// is believed when comparing Origin against the request's host.
	TrustedProxies []netip.Prefix
}

var (
	envOnce sync.Once
	envPol  *Policy
)

// envPolicy reads YARD_TRUSTED_ORIGINS (comma/space-separated origins) and
// YARD_TRUSTED_PROXIES (comma/space-separated IPs or CIDRs) once.
// Unparseable proxy entries are ignored rather than fatal: the guard then
// simply trusts less.
func envPolicy() *Policy {
	envOnce.Do(func() {
		envPol = &Policy{
			TrustedOrigins: fields(os.Getenv("YARD_TRUSTED_ORIGINS")),
			TrustedProxies: parsePrefixes(fields(os.Getenv("YARD_TRUSTED_PROXIES"))),
		}
	})
	return envPol
}

func fields(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' })
}

func parsePrefixes(list []string) []netip.Prefix {
	var out []netip.Prefix
	for _, s := range list {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
		} else if a, err := netip.ParseAddr(s); err == nil {
			out = append(out, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
		}
	}
	return out
}

// Guard wraps next with the cross-origin checks described on Policy.
func (p *Policy) Guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if code, msg := p.check(r); code != 0 {
			http.Error(w, msg, code)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func stateChanging(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// check answers 0 to let the request through, else a status and message.
func (p *Policy) check(r *http.Request) (int, string) {
	if !stateChanging(r.Method) {
		return 0, ""
	}
	const rejected = "cross-origin request rejected"
	site := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site")))
	origin := strings.TrimSpace(r.Header.Get("Origin"))

	sameOrigin := site == "same-origin"
	if origin != "" {
		switch {
		case p.trustedOrigin(origin):
			// An explicitly trusted origin may be another site (a proxy
			// name); it outranks the browser's same-site verdict.
			return 0, ""
		case !p.originMatchesHost(origin, r):
			return http.StatusForbidden, rejected
		}
		sameOrigin = true
	}
	if site == "cross-site" || site == "same-site" {
		return http.StatusForbidden, rejected
	}
	if hasBody(r) && !isJSON(r.Header.Get("Content-Type")) && !sameOrigin {
		return http.StatusUnsupportedMediaType, "Content-Type must be application/json"
	}
	return 0, ""
}

func hasBody(r *http.Request) bool {
	return r.ContentLength > 0 || (r.ContentLength < 0 && r.Body != nil && r.Body != http.NoBody) ||
		len(r.TransferEncoding) > 0
}

func isJSON(ct string) bool {
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}
	return mt == "application/json" || (strings.HasPrefix(mt, "application/") && strings.HasSuffix(mt, "+json"))
}

func (p *Policy) trustedOrigin(origin string) bool {
	for _, t := range p.TrustedOrigins {
		if strings.EqualFold(strings.TrimRight(t, "/"), origin) {
			return true
		}
	}
	return false
}

// originMatchesHost compares the Origin's host[:port] with the request's
// Host — or, from a trusted proxy, its X-Forwarded-Host. The scheme is
// ignored: behind a TLS-terminating proxy the browser says https while
// the yard sees plain http. "null" and malformed origins never match.
func (p *Policy) originMatchesHost(origin string, r *http.Request) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	if hostEqual(u, r.Host) {
		return true
	}
	if p.fromTrustedProxy(r) {
		// X-Forwarded-Host may be a list when proxies chain; the first
		// entry is the one the browser addressed.
		fh := r.Header.Get("X-Forwarded-Host")
		if i := strings.IndexByte(fh, ','); i >= 0 {
			fh = fh[:i]
		}
		if fh = strings.TrimSpace(fh); fh != "" && hostEqual(u, fh) {
			return true
		}
	}
	return false
}

// hostEqual compares an Origin URL with a Host header value. A Host
// without a port matches the Origin's scheme default, since browsers omit
// default ports from both.
func hostEqual(u *url.URL, host string) bool {
	if strings.EqualFold(u.Host, host) {
		return true
	}
	oh, op := u.Hostname(), u.Port()
	if op == "" {
		op = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	hh, hp, err := net.SplitHostPort(host)
	if err != nil {
		hh, hp = strings.Trim(host, "[]"), ""
	}
	if hp == "" {
		hp = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	return strings.EqualFold(oh, hh) && op == hp
}

func (p *Policy) fromTrustedProxy(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return p.trusted(host)
}

func (p *Policy) trusted(host string) bool {
	if len(p.TrustedProxies) == 0 {
		return false
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	a = a.Unmap()
	for _, pr := range p.TrustedProxies {
		if pr.Contains(a) {
			return true
		}
	}
	return false
}

// ClientIP answers the address of the client behind r: the TCP peer, or —
// when the peer is one of YARD_TRUSTED_PROXIES — the right-most
// X-Forwarded-For hop that is not itself a trusted proxy. A client cannot
// spoof it by sending its own X-Forwarded-For to an untrusted listener.
func ClientIP(r *http.Request) string { return envPolicy().ClientIP(r) }

// ClientIP is the Policy-scoped form of the package-level ClientIP.
func (p *Policy) ClientIP(r *http.Request) string {
	peer, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		peer = r.RemoteAddr
	}
	if !p.trusted(peer) {
		return peer
	}
	hops := fields(strings.Join(r.Header.Values("X-Forwarded-For"), ","))
	for i := len(hops) - 1; i >= 0; i-- {
		if _, err := netip.ParseAddr(hops[i]); err != nil {
			break // garbage: stop at the last address we could vouch for
		}
		peer = hops[i]
		if !p.trusted(peer) {
			break
		}
	}
	return peer
}
