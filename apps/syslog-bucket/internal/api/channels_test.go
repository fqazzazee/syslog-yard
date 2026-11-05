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
