// Package config reads runtime configuration from environment variables.
package config

import "os"

type Config struct {
	// DatabaseURL is a pgx/libpq connection string.
	DatabaseURL string
	// APIAddr is the listen address for the REST API + SPA (e.g. ":8080").
	APIAddr string
	// IngestAddr is the TCP listen address where syslog-ng delivers
	// newline-delimited JSON records (e.g. ":6601").
	IngestAddr string
}

func FromEnv() Config {
	return Config{
		DatabaseURL: getenv("BUCKET_DB_URL", "postgres://syslog_bucket:syslog_bucket@localhost:5432/syslog_bucket?sslmode=disable"),
		APIAddr:     getenv("BUCKET_API_ADDR", ":8080"),
		IngestAddr:  getenv("BUCKET_INGEST_ADDR", ":6601"),
	}
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
