// Syshose — a containerized web app that generates realistic syslog streams.
package main

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/tesla/syshose/internal/engine"
	"github.com/tesla/syshose/internal/preset"
	"github.com/tesla/syshose/internal/server"
	"github.com/tesla/syshose/web"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	addr := env("SYSHOSE_ADDR", ":8080")
	dataDir := env("SYSHOSE_DATA", "/data")

	// Fall back to ./data when /data isn't writable (bare local runs).
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		fallback := "./data"
		fmt.Fprintf(os.Stderr, "syshose: %s not writable (%v), using %s\n", dataDir, err, fallback)
		dataDir = fallback
		if err := os.MkdirAll(dataDir, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "syshose: cannot create data dir: %v\n", err)
			os.Exit(1)
		}
	}

	store, err := preset.NewStore(dataDir + "/presets")
	if err != nil {
		fmt.Fprintf(os.Stderr, "syshose: loading presets: %v\n", err)
		os.Exit(1)
	}
	mgr, err := engine.NewManager(store, dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "syshose: loading jobs: %v\n", err)
		os.Exit(1)
	}

	ui, err := web.Dist()
	if err != nil {
		fmt.Fprintf(os.Stderr, "syshose: embedded UI missing: %v\n", err)
		os.Exit(1)
	}

	srv := &http.Server{Addr: addr, Handler: server.New(mgr, store, ui)}
	go func() {
		fmt.Printf("syshose listening on %s (data dir %s, %d presets)\n",
			addr, dataDir, len(store.List()))
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "syshose: %v\n", err)
			os.Exit(1)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	fmt.Println("syshose: shutting down, stopping all jobs")
	mgr.StopAll()
	srv.Close()
}
