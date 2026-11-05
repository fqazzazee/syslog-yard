package api

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/syslog-yard/syslog-bucket/internal/store"
)

func smtpChannel(cfg string) store.Channel {
	return store.Channel{Kind: "smtp", Config: json.RawMessage(cfg)}
}

func passwordOf(t *testing.T, raw json.RawMessage) any {
	t.Helper()
	m := map[string]any{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal %s: %v", raw, err)
	}
	if _, ok := m["has_password"]; ok {
		t.Errorf("has_password must never be persisted: %s", raw)
	}
	return m["password"]
}

func TestMergeSecretsKeepsPasswordForSameTarget(t *testing.T) {
	existing := smtpChannel(`{"host":"mail.example.com","port":587,"username":"bot","password":"s3cret","tls":"starttls","from":"a@x","to":["b@x"]}`)
	cases := map[string]string{
		"identical":           `{"host":"mail.example.com","port":587,"username":"bot","password":"","tls":"starttls","from":"a@x","to":["b@x"]}`,
		"recipients changed":  `{"host":"mail.example.com","port":587,"username":"bot","password":"","tls":"starttls","from":"c@x","to":["d@x"]}`,
		"defaults normalised": `{"host":"Mail.Example.com ","username":"bot","password":"","has_password":true,"from":"a@x","to":["b@x"]}`,
	}
	for name, cfg := range cases {
		out, err := mergeSecrets(existing, smtpChannel(cfg))
		if err != nil {
			t.Fatalf("%s: unexpected error %v", name, err)
		}
		if got := passwordOf(t, out); got != "s3cret" {
			t.Errorf("%s: password = %v, want stored one kept", name, got)
		}
	}
}

func TestMergeSecretsDiscardsPasswordWhenTargetChanges(t *testing.T) {
	existing := smtpChannel(`{"host":"mail.example.com","port":587,"username":"bot","password":"s3cret","tls":"starttls"}`)
	changed := map[string]string{
		"host":     `{"host":"evil.example.net","port":587,"username":"bot","password":"","tls":"starttls"}`,
		"port":     `{"host":"mail.example.com","port":2525,"username":"bot","password":"","tls":"starttls"}`,
		"username": `{"host":"mail.example.com","port":587,"username":"other","password":"","tls":"starttls"}`,
		"tls":      `{"host":"mail.example.com","port":587,"username":"bot","password":"","tls":"none"}`,
	}
	for name, cfg := range changed {
		_, err := mergeSecrets(existing, smtpChannel(cfg))
		if !errors.Is(err, errSecretReentry) {
			t.Errorf("%s changed with blank password: err = %v, want errSecretReentry", name, err)
		}
	}

	// A fresh password for the new target is accepted as-is.
	out, err := mergeSecrets(existing, smtpChannel(`{"host":"evil.example.net","username":"bot","password":"new-one"}`))
	if err != nil || passwordOf(t, out) != "new-one" {
		t.Errorf("explicit new password: out=%s err=%v", out, err)
	}

	// Moving to an unauthenticated relay drops the stored secret silently.
	out, err = mergeSecrets(existing, smtpChannel(`{"host":"relay.internal","username":"","password":""}`))
	if err != nil {
		t.Fatalf("no-auth relay: %v", err)
	}
	if got := passwordOf(t, out); got != "" {
		t.Errorf("no-auth relay kept password %v", got)
	}

	// Switching kind never carries the SMTP password into the new config.
	out, err = mergeSecrets(existing, store.Channel{Kind: "webhook", Config: json.RawMessage(`{"url":"https://h.example/x","password":""}`)})
	if err != nil {
		t.Fatalf("kind change: %v", err)
	}
	if got := passwordOf(t, out); got != "" {
		t.Errorf("kind change kept password %v", got)
	}
}

func TestRedactConfigMasksURLsForViewers(t *testing.T) {
	raw := json.RawMessage(`{"url":"https://hooks.slack.com/services/T000/B000/XXXXSECRET"}`)

	viewer := map[string]any{}
	if err := json.Unmarshal(redactConfig(raw, false), &viewer); err != nil {
		t.Fatal(err)
	}
	if viewer["url"] != "https://hooks.slack.com/…" || viewer["has_url"] != true {
		t.Errorf("viewer config = %v, want masked url + has_url", viewer)
	}

	editor := map[string]any{}
	if err := json.Unmarshal(redactConfig(raw, true), &editor); err != nil {
		t.Fatal(err)
	}
	if editor["url"] != "https://hooks.slack.com/services/T000/B000/XXXXSECRET" {
		t.Errorf("editor should see the full url, got %v", editor["url"])
	}
	if _, ok := editor["has_url"]; ok {
		t.Errorf("editor config should be unchanged, got %v", editor)
	}

	// Passwords are blanked for everyone.
	for _, ed := range []bool{true, false} {
		m := map[string]any{}
		if err := json.Unmarshal(redactConfig(json.RawMessage(`{"host":"m","password":"pw"}`), ed), &m); err != nil {
			t.Fatal(err)
		}
		if m["password"] != "" || m["has_password"] != true {
			t.Errorf("editor=%v: password not redacted: %v", ed, m)
		}
	}

	// Garbage never reaches a viewer verbatim.
	if got := string(redactConfig(json.RawMessage(`"https://x/secret"`), false)); got != "{}" {
		t.Errorf("unparseable config for viewer = %s, want {}", got)
	}
}

func TestScrubURLs(t *testing.T) {
	in := `Post "https://user:pw@hooks.slack.com/services/T/B/SECRET?x=1": dial tcp: lookup failed`
	want := `Post "https://hooks.slack.com/…": dial tcp: lookup failed`
	if got := scrubURLs(in); got != want {
		t.Errorf("scrubURLs = %q, want %q", got, want)
	}
	if got := scrubURLs("rate limited"); got != "rate limited" {
		t.Errorf("plain text changed: %q", got)
	}
}

func TestCanEditChannels(t *testing.T) {
	for role, want := range map[string]bool{store.RoleAdmin: true, store.RoleAnalyst: true, store.RoleViewer: false} {
		if got := canEditChannels(&store.User{Role: role}); got != want {
			t.Errorf("%s: got %v want %v", role, got, want)
		}
	}
	if canEditChannels(nil) {
		t.Error("nil user must not be an editor")
	}
}
