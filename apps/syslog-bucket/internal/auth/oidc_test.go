package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/syslog-yard/syslog-bucket/internal/store"
)

// fakeIdP is a minimal OpenID provider: discovery, JWKS, and a token
// endpoint that enforces PKCE and signs an RS256 ID token carrying whatever
// nonce the test tells it to.
type fakeIdP struct {
	t   *testing.T
	srv *httptest.Server
	key *rsa.PrivateKey

	mu        sync.Mutex
	challenge string // code_challenge seen at the authorize step
	nonce     string // nonce to put in the ID token
}

func newFakeIdP(t *testing.T) *fakeIdP {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIdP{t: t, key: key}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                f.srv.URL,
			"authorization_endpoint":                f.srv.URL + "/authorize",
			"token_endpoint":                        f.srv.URL + "/token",
			"jwks_uri":                              f.srv.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		b64 := base64.RawURLEncoding.EncodeToString
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig",
			"n": b64(key.N.Bytes()), "e": b64(big.NewInt(int64(key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		f.mu.Lock()
		challenge, nonce := f.challenge, f.nonce
		f.mu.Unlock()
		if r.PostForm.Get("code") != "good-code" || base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(`{"error":"invalid_grant","error_description":"IDP-INTERNAL-DETAIL"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "at", "token_type": "Bearer", "expires_in": 60,
			"id_token": f.sign(map[string]any{
				"iss": f.srv.URL, "aud": "bucket", "sub": "subject-123",
				"iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(),
				"nonce": nonce, "preferred_username": "sso-user", "email": "u@example.com",
			}),
		})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIdP) sign(claims map[string]any) string {
	b64 := base64.RawURLEncoding.EncodeToString
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "k1", "typ": "JWT"})
	body, _ := json.Marshal(claims)
	signing := b64(hdr) + "." + b64(body)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, sum[:])
	if err != nil {
		f.t.Fatal(err)
	}
	return signing + "." + b64(sig)
}

// startLogin runs HandleOIDCLogin and returns the flow cookie and the query
// of the redirect to the IdP.
func startLogin(t *testing.T, svc *Service) (*http.Cookie, url.Values) {
	t.Helper()
	w := httptest.NewRecorder()
	svc.HandleOIDCLogin(w, httptest.NewRequest("GET", "/api/auth/oidc/login", nil))
	if w.Code != http.StatusFound {
		t.Fatalf("login: status %d: %s", w.Code, w.Body)
	}
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	var cookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == stateCookie {
			cookie = c
		}
	}
	if cookie == nil || !cookie.HttpOnly {
		t.Fatalf("login set no HttpOnly flow cookie: %v", w.Result().Cookies())
	}
	return cookie, loc.Query()
}

func TestOIDCLoginSendsPKCEAndNonce(t *testing.T) {
	idp := newFakeIdP(t)
	svc := New(nil, false)
	svc.SetOIDC(&OIDC{Issuer: idp.srv.URL, ClientID: "bucket", ClientSecret: "s", RedirectURL: "http://bucket/cb"})

	cookie, q := startLogin(t, svc)
	f, ok := decodeFlowState(cookie.Value)
	if !ok {
		t.Fatalf("undecodable flow cookie %q", cookie.Value)
	}
	if q.Get("state") != f.State || q.Get("nonce") != f.Nonce {
		t.Errorf("state/nonce in redirect %v don't match cookie %+v", q, f)
	}
	sum := sha256.Sum256([]byte(f.Verifier))
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") != base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Errorf("missing/incorrect PKCE S256 challenge in %v", q)
	}
}

func TestOIDCRedeem(t *testing.T) {
	idp := newFakeIdP(t)
	o := &OIDC{Issuer: idp.srv.URL, ClientID: "bucket", ClientSecret: "s", RedirectURL: "http://bucket/cb"}
	svc := New(nil, false)
	svc.SetOIDC(o)
	cookie, q := startLogin(t, svc)
	f, _ := decodeFlowState(cookie.Value)
	idp.challenge = q.Get("code_challenge")
	ctx := context.Background()

	idp.nonce = f.Nonce
	id, _, err := o.redeem(ctx, "good-code", f)
	if err != nil {
		t.Fatalf("valid flow rejected: %v", err)
	}
	if id.Subject != "subject-123" || id.PreferredUsername != "sso-user" || id.Email != "u@example.com" {
		t.Errorf("identity = %+v", id)
	}

	idp.nonce = "someone-elses-nonce"
	if _, step, err := o.redeem(ctx, "good-code", f); err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Errorf("replayed token with foreign nonce accepted (step %q, err %v)", step, err)
	}

	idp.nonce = f.Nonce
	wrong := f
	wrong.Verifier = "x" + f.Verifier[1:]
	if _, step, err := o.redeem(ctx, "good-code", wrong); err == nil || step != "code exchange" {
		t.Errorf("code redeemed without the right PKCE verifier (step %q, err %v)", step, err)
	}
}

func TestOIDCCallbackHidesProviderErrors(t *testing.T) {
	idp := newFakeIdP(t)
	svc := New(nil, false)
	svc.SetOIDC(&OIDC{Issuer: idp.srv.URL, ClientID: "bucket", ClientSecret: "s", RedirectURL: "http://bucket/cb"})
	cookie, q := startLogin(t, svc)
	idp.challenge = q.Get("code_challenge")

	call := func(query string, withCookie bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/api/auth/oidc/callback?"+query, nil)
		if withCookie {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		svc.HandleOIDCCallback(w, r)
		return w
	}
	state := url.QueryEscape(q.Get("state"))

	if w := call("state=wrong&code=good-code", true); w.Code != http.StatusBadRequest {
		t.Errorf("state mismatch: got %d", w.Code)
	}
	if w := call("state="+state+"&code=good-code", false); w.Code != http.StatusBadRequest {
		t.Errorf("missing flow cookie: got %d", w.Code)
	}
	w := call("state="+state+"&code=bad-code", true)
	if w.Code != http.StatusBadGateway || strings.Contains(w.Body.String(), "IDP-INTERNAL-DETAIL") ||
		strings.Contains(w.Body.String(), "invalid_grant") {
		t.Errorf("token error leaked or wrong status: %d %q", w.Code, w.Body)
	}
	w = call("state="+state+"&error=access_denied&error_description=%3Cscript%3E", true)
	if w.Code != http.StatusUnauthorized || strings.Contains(w.Body.String(), "script") {
		t.Errorf("IdP error reflected or wrong status: %d %q", w.Code, w.Body)
	}
}

func TestOIDCDefaultRoleIsViewer(t *testing.T) {
	if DefaultOIDCRole != store.RoleViewer {
		t.Fatalf("DefaultOIDCRole = %q, want viewer", DefaultOIDCRole)
	}
}
