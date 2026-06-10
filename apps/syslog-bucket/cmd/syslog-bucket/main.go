package main

import (
	"context"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/syslog-yard/syslog-bucket/internal/api"
	"github.com/syslog-yard/syslog-bucket/internal/config"
	"github.com/syslog-yard/syslog-bucket/internal/engine"
	"github.com/syslog-yard/syslog-bucket/internal/ingest"
	"github.com/syslog-yard/syslog-bucket/internal/parsers"
	"github.com/syslog-yard/syslog-bucket/internal/store"
	"github.com/syslog-yard/syslog-bucket/internal/ws"
	"github.com/syslog-yard/syslog-bucket/web"
)

func main() {
	if err := run(); err != nil {
		slog.Error("fatal", "error", err)
		os.Exit(1)
	}
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

	eng := engine.New(st)
	if err := eng.Reload(ctx); err != nil {
		return err
	}
	go eng.Run(ctx)

	hub := ws.NewHub()

	registry := parsers.NewRegistry(parsers.Generic{})
	ing := ingest.New(st, registry, eng, hub, cfg.IngestAddr)

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
		Handler: api.New(st, eng, hub, dist, hints),
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
