package api

import "net/http"

// Content-Security-Policy for the embedded SPA. Scripts are external,
// content-hashed bundles ('self'); inline styles are needed for React
// style props and runtime-injected stylesheets; connect-src 'self' covers
// the same-origin REST API plus the live-tail WebSocket. frame-ancestors
// 'none' blocks clickjacking of the login form. No third-party origins:
// the UI ships self-contained.
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

// secureHeaders adds baseline hardening headers to every response. HSTS is
// deliberately omitted: it only helps over HTTPS and would wedge the
// http-on-localhost lab flow — enable it at the reverse proxy in
// production (see docs/SECURITY.md). This helper is duplicated verbatim in
// syslog-hose and syslog-valve; keep the three in sync.
func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}
