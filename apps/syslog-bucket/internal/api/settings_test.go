package api

import (
	"errors"
	"testing"
)

func TestKeepClientSecret(t *testing.T) {
	prev := oidcSettings{Enabled: true, Issuer: "https://idp.example.com/realms/yard", ClientSecret: "s3cret"}
	cases := []struct {
		name    string
		in      oidcSettings
		want    string
		wantErr error
	}{
		{"same issuer keeps", oidcSettings{Enabled: true, Issuer: "https://idp.example.com/realms/yard"}, "s3cret", nil},
		{"trailing slash is the same issuer", oidcSettings{Enabled: true, Issuer: " https://idp.example.com/realms/yard/ "}, "s3cret", nil},
		{"new issuer must re-enter", oidcSettings{Enabled: true, Issuer: "https://evil.example.net"}, "", errIssuerSecretReentry},
		{"new issuer while disabled drops it", oidcSettings{Enabled: false, Issuer: "https://evil.example.net"}, "", nil},
		{"cleared issuer while disabled drops it", oidcSettings{Enabled: false}, "", nil},
	}
	for _, c := range cases {
		got, err := keepClientSecret(prev, c.in)
		if got != c.want || !errors.Is(err, c.wantErr) {
			t.Errorf("%s: got (%q, %v), want (%q, %v)", c.name, got, err, c.want, c.wantErr)
		}
	}
	if got, err := keepClientSecret(oidcSettings{}, oidcSettings{Enabled: true, Issuer: "https://x"}); got != "" || err != nil {
		t.Errorf("no previous secret: got (%q, %v)", got, err)
	}
}
