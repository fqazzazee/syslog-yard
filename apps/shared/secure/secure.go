// Package secure carries the hardening headers every yard UI serves.
// One body instead of a per-app copy: the suite's security posture is
// deliberately identical across hose, valve and bucket.
package secure

import "net/http"

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

// Headers adds baseline hardening headers to every response. HSTS is
// deliberately omitted: it only helps over HTTPS and would wedge the
// http-on-localhost lab flow — enable it at the reverse proxy in
// production (see docs/SECURITY.md).
func Headers(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}
