package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/syslog-yard/syslog-bucket/internal/api"
	"github.com/syslog-yard/syslog-bucket/internal/auth"
	"github.com/syslog-yard/syslog-bucket/internal/config"
	"github.com/syslog-yard/syslog-bucket/internal/engine"
	"github.com/syslog-yard/syslog-bucket/internal/ingest"
	"github.com/syslog-yard/syslog-bucket/internal/netfeeds"
	"github.com/syslog-yard/syslog-bucket/internal/notify"
	"github.com/syslog-yard/syslog-bucket/internal/parsers"
	"github.com/syslog-yard/syslog-bucket/internal/store"
	"github.com/syslog-yard/syslog-bucket/internal/ws"
	"github.com/syslog-yard/syslog-bucket/web"
)

func main() {
	// Subcommands run a one-off operation against the database instead of
	// starting the server (e.g. `syslog-bucket reset-admin`).
	if len(os.Args) > 1 {
		if err := runCommand(os.Args[1], os.Args[2:]); err != nil {
			slog.Error("fatal", "error", err)
			os.Exit(1)
		}
		return
	}
	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func runCommand(name string, args []string) error {
	switch name {
	case "reset-admin":
		return resetAdmin(args)
	default:
		return fmt.Errorf("unknown command %q (known: reset-admin)", name)
	}
}

// resetAdmin resets (or creates) the admin account's password, printing the
// new one. With no argument a random password is generated; pass a password
// to set a known one.
func resetAdmin(args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cfg := config.FromEnv()
	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.Migrate(ctx); err != nil {
		return err
	}

	password := ""
	if len(args) > 0 {
		password = args[0]
	}
	password, err = auth.ResetAdmin(ctx, st, password)
	if err != nil {
		return err
	}
	fmt.Printf("admin password reset to: %s\n", password)
	return nil
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg := config.FromEnv()

	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer st.Close()

	if err := st.Migrate(ctx); err != nil {
		return err
	}

	if err := auth.Bootstrap(ctx, st, cfg.AdminPassword); err != nil {
		return err
	}
	if _, err := st.SeedDefaultBuckets(ctx); err != nil {
		return err
	}
	// OIDC and the session idle timeout are loaded from the DB (falling back to
	// env) and applied inside api.New, so they can be reconfigured at runtime.
	authSvc := auth.New(st, cfg.CookieSecure)

	eng := engine.New(st)
	if err := eng.Reload(ctx); err != nil {
		return err
	}
	go eng.Run(ctx)

	hub := ws.NewHub()

	dispatcher := notify.New(st)
	if err := dispatcher.Reload(ctx); err != nil {
		return err
	}
	go dispatcher.Run(ctx)

	// Network-view category sets: threat-intel / O365 feeds plus custom CIDR
	// groups. Cached snapshots load synchronously; fetching runs in the
	// background so an offline start still serves the static scopes.
	netMgr := netfeeds.New(st)
	netMgr.Load(ctx)
	go netMgr.Run(ctx)

	registry := parsers.NewRegistry(parsers.Generic{})
	ing := ingest.New(st, registry, eng, hub, dispatcher, cfg.IngestAddr)

	ingestErr := make(chan error, 1)
	go func() { ingestErr <- ing.Run(ctx) }()

	dist, err := fs.Sub(web.Dist, "dist")
	if err != nil {
		return err
	}
	// Links to the neighbor yard UIs for the cross-tool nav (full URL or
	// bare port; absent when running standalone).
	hints := map[string]string{}
	for envKey, hintKey := range map[string]string{
		"YARD_LINK_HOSE":   "linkHose",
		"YARD_LINK_VALVE":  "linkValve",
		"YARD_LINK_BUCKET": "linkBucket",
	} {
		if v := os.Getenv(envKey); v != "" {
			hints[hintKey] = v
		}
	}
	httpSrv := &http.Server{
		Addr:    cfg.APIAddr,
		Handler: api.New(st, eng, hub, dispatcher, dist, hints, authSvc, cfg, netMgr),
	}
	httpErr := make(chan error, 1)
	go func() {
		slog.Info("api listening", "addr", cfg.APIAddr)
		httpErr <- httpSrv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		slog.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		httpSrv.Shutdown(shutdownCtx)
		return nil
	case err := <-ingestErr:
		return err
	case err := <-httpErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
