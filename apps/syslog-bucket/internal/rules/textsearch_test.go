package rules

import (
	"context"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

const (
	sshMsg  = "Failed password for admin from 10.0.0.5 port 22 ssh2"
	fwMsg   = "deny tcp src=192.168.1.10:51515 dst=fw1.example.com:443 user@example.com policy foo-bar"
	pathMsg = "sshd[1234]: session opened for /var/log/syslog-ng by root(uid=0) 2024-01-01"
	urlMsg  = "GET https://evil.example/a.php from 2.56.192.0/22 x-1 it's ÄÖ Straße"
)

// textParity pins websearch semantics; TestTextParityPostgres checks every
// row against a real server when BUCKET_TEST_DSN is set.
var textParity = []struct {
	msg, query string
	want       bool
}{
	// Whole lexemes, not substrings.
	{sshMsg, "admin", true},
	{sshMsg, "adm", false},
	{sshMsg, "pass", false},
	{sshMsg, "FAILED", true},
	{sshMsg, "failed admin", true},
	{sshMsg, "failed root", false},
	// Numbers and addresses are single lexemes.
	{sshMsg, "10.0.0.5", true},
	{sshMsg, "10.0.0", false},
	{sshMsg, "22", true},
	{sshMsg, "2", false},
	{sshMsg, "ssh2", true},
	// or / -negation / phrases.
	{sshMsg, "root or admin", true},
	{sshMsg, "root OR guest", false},
	{sshMsg, "admin -root", true},
	{sshMsg, "admin -failed", false},
	{sshMsg, "-root", true},
	{sshMsg, `"failed password"`, true},
	{sshMsg, `"password failed"`, false},
	{sshMsg, `"failed admin"`, false},
	{sshMsg, `-"failed password"`, false},
	{sshMsg, `"password for" or nothing`, true},
	{sshMsg, "nothing or failed root", false},
	{sshMsg, "failed root or port", true},
	{sshMsg, "or admin", false},   // leading `or` is a word
	{sshMsg, "admin or", false},   // so is a trailing one
	{sshMsg, "admin or or", true}, // admin | 'or'
	{sshMsg, "root or or", false}, // first `or` is the operator, second a word
	{sshMsg, "admin --failed", true},
	{sshMsg, "admin - failed", false},
	{sshMsg, "", false},
	{sshMsg, `""`, false},
	{sshMsg, "admin|failed", true},
	{sshMsg, "admin & !root", false}, // operator characters are plain separators
	{sshMsg, "admin !failed", true},
	// Hosts, e-mail, key=value, compounds.
	{fwMsg, "fw1.example.com:443", false}, // host:port is one msg lexeme, but `:` splits the query
	{fwMsg, "fw1.example.com", false},
	{sshMsg + " via fw1.example.com.", "fw1.example.com", true},
	{fwMsg, "example.com", false},
	{fwMsg, "user@example.com", true},
	{fwMsg, "user", false},
	{fwMsg, "192.168.1.10", true},
	{fwMsg, "443", false},
	{fwMsg, "51515", true},
	{fwMsg, "dst", true},
	{fwMsg, "src=192.168.1.10", true},
	{fwMsg, "foo-bar", true},
	{fwMsg, "foo", true},
	{fwMsg, "bar foo", true},
	{fwMsg, "bar-foo", false},
	{fwMsg, `"deny tcp src"`, true},
	// Paths, brackets, dates.
	{pathMsg, "sshd", true},
	{pathMsg, "1234", true},
	{pathMsg, "sshd[1234]", true},
	{pathMsg, "/var/log/syslog-ng", true},
	{pathMsg, "syslog-ng", false},
	{pathMsg, "uid", true},
	{pathMsg, "2024", true},
	{pathMsg, "2024-01-01", true},
	{pathMsg, "01", false},
	{pathMsg, "root uid", true},
	// URLs, CIDRs, signed numbers, apostrophes, Unicode.
	{urlMsg, "evil.example", true},
	{urlMsg, "https", false},
	{urlMsg, "2.56.192.0", true},
	{urlMsg, "22", false},
	{urlMsg, "x", true},
	{urlMsg, "1", false},
	{urlMsg, "it", true},
	{urlMsg, "s", true},
	{urlMsg, "äö", true},
	{urlMsg, "straße", true},
}

func TestTextParity(t *testing.T) {
	for _, c := range textParity {
		if got := textMatch(c.msg, c.query); got != c.want {
			t.Errorf("textMatch(%q, %q) = %v, want %v", c.msg, c.query, got, c.want)
		}
	}
}

func TestLexemes(t *testing.T) {
	for in, want := range map[string][]string{
		"Failed password for admin":      {"failed", "password", "for", "admin"},
		"from 10.0.0.5 port 22":          {"from", "10.0.0.5", "port", "22"},
		"foo-bar baz":                    {"foo-bar", "foo", "bar", "baz"},
		"sshd[123]: 2024-01-01":          {"sshd", "123", "2024", "-01", "-01"},
		"conn_id=12 user@example.com":    {"conn", "id", "12", "user@example.com"},
		"/var/log/messages end.":         {"/var/log/messages", "end"},
		"192.168.1.1/24":                 {"192.168.1.1", "/24"},
		"https://x.com/path":             {"x.com/path", "x.com", "/path"},
		"dst=fw1.example.com:443 a.b:22": {"dst", "fw1.example.com:443", "a.b", "22"},
		"host.com:80/x":                  {"host.com:80/x", "host.com:80", "/x"},
	} {
		if got := lexemes(in); !slices.Equal(got, want) {
			t.Errorf("lexemes(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestTextParityPostgres runs every parity row through
// to_tsvector('simple', msg) @@ websearch_to_tsquery('simple', query).
func TestTextParityPostgres(t *testing.T) {
	dsn := os.Getenv("BUCKET_TEST_DSN")
	if dsn == "" {
		t.Skip("BUCKET_TEST_DSN not set; skipping Postgres parity check")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	for _, c := range textParity {
		var pg bool
		if err := conn.QueryRow(ctx,
			`SELECT to_tsvector('simple', $1) @@ websearch_to_tsquery('simple', $2)`, c.msg, c.query).Scan(&pg); err != nil {
			t.Fatalf("%q: %v", c.query, err)
		}
		if pg != c.want {
			t.Errorf("table disagrees with Postgres: (%q, %q) want %v, Postgres says %v", c.msg, c.query, c.want, pg)
		}
	}
}
