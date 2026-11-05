// Package config reads runtime configuration from environment variables.
package config

import (
	"os"
	"strings"
)

type Config struct {
	// DatabaseURL is a pgx/libpq connection string.
	DatabaseURL string
	// APIAddr is the listen address for the REST API + SPA (e.g. ":8080").
	APIAddr string
	// IngestAddr is the TCP listen address where syslog-ng delivers
	// newline-delimited JSON records (e.g. ":6601").
	IngestAddr string

	// AdminPassword seeds the initial admin account on first start; when
	// empty a random password is generated and logged once.
	AdminPassword string
	// CookieSecure marks session cookies Secure — set when serving the UI
	// over HTTPS (typically behind a reverse proxy).
	CookieSecure bool

	// OIDC enables SSO when OIDCIssuer is non-empty. RedirectURL must be
	// the externally visible <ui-base>/api/auth/oidc/callback.
	OIDCIssuer       string
	OIDCClientID     string
	OIDCClientSecret string
	OIDCRedirectURL  string
	OIDCName         string // login-button label
	OIDCDefaultRole  string // role for auto-provisioned users

	// WSOrigins lists extra Origin host patterns (path.Match syntax, e.g.
	// "localhost:5173") allowed to open the live-tail WebSocket. Same-origin
	// is always allowed; leave empty outside development.
	WSOrigins []string

	// TrustedProxies is a comma-separated list of IPs/CIDRs of proxies (the
	// hose/valve auth proxy, a reverse proxy) whose X-Forwarded-For the login
	// throttle believes. Shared with the other yard tools as
	// YARD_TRUSTED_PROXIES. Empty means the TCP peer is always the client.
	TrustedProxies string
}

func FromEnv() Config {
	return Config{
		DatabaseURL: getenv("BUCKET_DB_URL", "postgres://syslog_bucket:syslog_bucket@localhost:5432/syslog_bucket?sslmode=disable"),
		APIAddr:     getenv("BUCKET_API_ADDR", ":8080"),
		IngestAddr:  getenv("BUCKET_INGEST_ADDR", ":6601"),

		AdminPassword: os.Getenv("BUCKET_ADMIN_PASSWORD"),
		CookieSecure:  os.Getenv("BUCKET_COOKIE_SECURE") == "true",

		OIDCIssuer:       os.Getenv("BUCKET_OIDC_ISSUER"),
		OIDCClientID:     os.Getenv("BUCKET_OIDC_CLIENT_ID"),
		OIDCClientSecret: os.Getenv("BUCKET_OIDC_CLIENT_SECRET"),
		OIDCRedirectURL:  os.Getenv("BUCKET_OIDC_REDIRECT_URL"),
		OIDCName:         getenv("BUCKET_OIDC_NAME", "SSO"),
		OIDCDefaultRole:  getenv("BUCKET_OIDC_DEFAULT_ROLE", "viewer"), // read-only until promoted

		WSOrigins:      splitList(os.Getenv("BUCKET_WS_ORIGINS")),
		TrustedProxies: os.Getenv("YARD_TRUSTED_PROXIES"),
	}
}

// splitList parses a comma-separated env value, dropping blanks.
func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
