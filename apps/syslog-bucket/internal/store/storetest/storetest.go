// Package storetest gives tests a freshly migrated, throwaway Postgres
// database. Tests using it are skipped unless BUCKET_TEST_DSN points at a
// server where the role may CREATE DATABASE, e.g.
//
//	podman run -d --rm -p 55432:5432 -e POSTGRES_PASSWORD=pw postgres:17-alpine
//	BUCKET_TEST_DSN=postgres://postgres:pw@localhost:55432/postgres go test ./...
package storetest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/syslog-yard/syslog-bucket/internal/store"
)

// New creates a uniquely named database, migrates it, and drops it when the
// test ends.
func New(t testing.TB) *store.Store {
	t.Helper()
	dsn := os.Getenv("BUCKET_TEST_DSN")
	if dsn == "" {
		t.Skip("BUCKET_TEST_DSN not set; skipping Postgres-backed test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	admin, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect %s: %v", dsn, err)
	}
	defer admin.Close(ctx)
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := "bucket_test_" + hex.EncodeToString(b)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create database: %v", err)
	}

	u, err := url.Parse(dsn)
	if err != nil || u.Scheme == "" {
		t.Fatalf("BUCKET_TEST_DSN must be a postgres:// URL: %v", err)
	}
	u.Path = "/" + name
	st, err := store.Open(ctx, u.String())
	if err != nil {
		t.Fatalf("open test database: %v", err)
	}
	t.Cleanup(func() {
		st.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if c, err := pgx.Connect(ctx, dsn); err == nil {
			_, _ = c.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
			c.Close(ctx)
		}
	})
	if err := st.Migrate(ctx); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return st
}
