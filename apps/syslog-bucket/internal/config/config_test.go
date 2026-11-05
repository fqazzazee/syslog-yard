package config

import (
	"slices"
	"testing"
)

var envKeys = []string{
	"BUCKET_DB_URL", "BUCKET_API_ADDR", "BUCKET_INGEST_ADDR", "BUCKET_ADMIN_PASSWORD",
	"BUCKET_COOKIE_SECURE", "BUCKET_OIDC_ISSUER", "BUCKET_OIDC_CLIENT_ID",
	"BUCKET_OIDC_CLIENT_SECRET", "BUCKET_OIDC_REDIRECT_URL", "BUCKET_OIDC_NAME",
	"BUCKET_OIDC_DEFAULT_ROLE", "BUCKET_WS_ORIGINS",
}

func clearEnv(t *testing.T) {
	for _, k := range envKeys {
		t.Setenv(k, "")
	}
}

// The defaults are secure: no admin password (one is generated), plain
// cookies only until asked, SSO users start read-only.
func TestFromEnvDefaults(t *testing.T) {
	clearEnv(t)
	c := FromEnv()
	if c.APIAddr != ":8080" || c.IngestAddr != ":6601" || c.DatabaseURL == "" {
		t.Errorf("listen/database defaults = %q %q %q", c.APIAddr, c.IngestAddr, c.DatabaseURL)
	}
	if c.AdminPassword != "" || c.CookieSecure || c.OIDCIssuer != "" {
		t.Errorf("unexpected defaults: %+v", c)
	}
	if c.OIDCDefaultRole != "viewer" || c.OIDCName != "SSO" {
		t.Errorf("OIDC defaults = %q %q", c.OIDCDefaultRole, c.OIDCName)
	}
	if len(c.WSOrigins) != 0 {
		t.Errorf("WSOrigins = %v, want none", c.WSOrigins)
	}
}

func TestFromEnvOverrides(t *testing.T) {
	clearEnv(t)
	t.Setenv("BUCKET_DB_URL", "postgres://x")
	t.Setenv("BUCKET_API_ADDR", ":9")
	t.Setenv("BUCKET_COOKIE_SECURE", "true")
	t.Setenv("BUCKET_OIDC_DEFAULT_ROLE", "analyst")
	t.Setenv("BUCKET_WS_ORIGINS", " localhost:5173, ,*.example.com ")
	c := FromEnv()
	if c.DatabaseURL != "postgres://x" || c.APIAddr != ":9" || !c.CookieSecure || c.OIDCDefaultRole != "analyst" {
		t.Errorf("overrides not applied: %+v", c)
	}
	if want := []string{"localhost:5173", "*.example.com"}; !slices.Equal(c.WSOrigins, want) {
		t.Errorf("WSOrigins = %q, want %q", c.WSOrigins, want)
	}
	// Only the exact word turns Secure on.
	t.Setenv("BUCKET_COOKIE_SECURE", "1")
	if FromEnv().CookieSecure {
		t.Error(`BUCKET_COOKIE_SECURE=1 enabled Secure; only "true" does`)
	}
}
