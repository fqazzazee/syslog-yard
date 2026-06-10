// syslog-hose — a containerized web app that generates realistic syslog streams.
package main

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/syslog-yard/syslog-hose/internal/engine"
	"github.com/syslog-yard/syslog-hose/internal/preset"
	"github.com/syslog-yard/syslog-hose/internal/server"
	"github.com/syslog-yard/syslog-hose/internal/yardauth"
	"github.com/syslog-yard/syslog-hose/web"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	addr := env("HOSE_ADDR", ":8080")
	dataDir := env("HOSE_DATA", "/data")

	// Fall back to ./data when /data isn't writable (bare local runs).
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		fallback := "./data"
		fmt.Fprintf(os.Stderr, "syslog-hose: %s not writable (%v), using %s\n", dataDir, err, fallback)
		dataDir = fallback
		if err := os.MkdirAll(dataDir, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "syslog-hose: cannot create data dir: %v\n", err)
			os.Exit(1)
		}
	}

	store, err := preset.NewStore(dataDir + "/presets")
	if err != nil {
		fmt.Fprintf(os.Stderr, "syslog-hose: loading presets: %v\n", err)
		os.Exit(1)
	}
	mgr, err := engine.NewManager(store, dataDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "syslog-hose: loading jobs: %v\n", err)
		os.Exit(1)
	}

	ui, err := web.Dist()
	if err != nil {
		fmt.Fprintf(os.Stderr, "syslog-hose: embedded UI missing: %v\n", err)
		os.Exit(1)
	}

	// Suite hints: the deployment can suggest a default destination and
	// inject links to the neighbor UIs (see /api/hints). All optional —
	// standalone runs simply get an empty map.
	hints := map[string]string{}
	for envKey, hintKey := range map[string]string{
		"HOSE_SUGGESTED_DEST": "suggestedDest",
		"YARD_LINK_HOSE":      "linkHose",
		"YARD_LINK_VALVE":     "linkValve",
		"YARD_LINK_BUCKET":    "linkBucket",
	} {
		if v := os.Getenv(envKey); v != "" {
			hints[hintKey] = v
		}
	}

	// Yard auth: when YARD_AUTH_URL points at the bucket, its user accounts
	// guard this UI too (unset = open, standalone mode).
	guard := yardauth.New(os.Getenv("YARD_AUTH_URL"), os.Getenv("YARD_COOKIE_SECURE") == "true")
	if guard.Enabled() {
		fmt.Printf("syslog-hose: auth enforced via %s\n", os.Getenv("YARD_AUTH_URL"))
	}

	srv := &http.Server{Addr: addr, Handler: server.New(mgr, store, ui, hints, guard)}
	go func() {
		fmt.Printf("syslog-hose listening on %s (data dir %s, %d presets)\n",
			addr, dataDir, len(store.List()))
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "syslog-hose: %v\n", err)
			os.Exit(1)
		}
	}()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	fmt.Println("syslog-hose: shutting down, stopping all jobs")
	mgr.StopAll()
	srv.Close()
}
