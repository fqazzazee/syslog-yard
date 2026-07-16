module github.com/syslog-yard/syslog-bucket

go 1.25.0

require (
	github.com/coder/websocket v1.8.14
	github.com/coreos/go-oidc/v3 v3.18.0
	github.com/jackc/pgx/v5 v5.7.4
	github.com/syslog-yard/shared v0.0.0
	golang.org/x/crypto v0.31.0
	golang.org/x/oauth2 v0.36.0
)

// The shared module lives in this repo and is never published; the Docker
// build copies apps/ wholesale so the relative path holds there too.
replace github.com/syslog-yard/shared => ../shared

require (
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	golang.org/x/sync v0.10.0 // indirect
	golang.org/x/text v0.21.0 // indirect
)
