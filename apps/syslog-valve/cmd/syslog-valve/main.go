// syslog-valve — a visual control plane for syslog-ng: edit a flow graph in
// the web UI, apply it, and the supervised syslog-ng instance routes the
// traffic. Part of the syslog-yard suite.
package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/syslog-yard/shared/yardauth"
	"github.com/syslog-yard/syslog-valve/internal/codegen"
	"github.com/syslog-yard/syslog-valve/internal/notify"
	"github.com/syslog-yard/syslog-valve/internal/rotate"
	"github.com/syslog-yard/syslog-valve/internal/server"
	"github.com/syslog-yard/syslog-valve/internal/supervisor"
	"github.com/syslog-yard/syslog-valve/internal/tap"
	"github.com/syslog-yard/syslog-valve/web"
)

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func main() {
	addr := env("VALVE_ADDR", ":8081")
	dataDir := env("VALVE_DATA", "/data")
	bin := env("VALVE_SYSLOGNG_BIN", "syslog-ng")

	ngDir := filepath.Join(dataDir, "syslog-ng")
	if err := os.MkdirAll(ngDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "syslog-valve: cannot create data dir: %v\n", err)
		os.Exit(1)
	}

	sup := supervisor.New(bin, ngDir)
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// The live-tail tap must be listening before syslog-ng starts, or its
	// tap destinations error until the first time-reopen retry.
	tp := tap.New()
	if err := tp.Listen(ctx, codegen.TapSocket); err != nil {
		fmt.Fprintf(os.Stderr, "syslog-valve: live-tail tap: %v\n", err)
		os.Exit(1)
	}

	// The notify dispatcher listens on its own datagram socket (notify nodes
	// duplicate matched messages there); bind it before syslog-ng starts.
	nd := notify.New()
	if err := nd.Listen(ctx, codegen.NotifySocket); err != nil {
		fmt.Fprintf(os.Stderr, "syslog-valve: notify socket: %v\n", err)
		os.Exit(1)
	}

	if err := sup.Start(ctx, codegen.Minimal(sup.Version())); err != nil {
		fmt.Fprintf(os.Stderr, "syslog-valve: starting syslog-ng: %v\n", err)
		os.Exit(1)
	}

	ui, err := web.Dist()
	if err != nil {
		fmt.Fprintf(os.Stderr, "syslog-valve: embedded UI missing: %v\n", err)
		os.Exit(1)
	}

	hints := map[string]string{}
	if v := os.Getenv("VALVE_SUGGESTED_FORWARD"); v != "" {
		hints["suggestedForward"] = v
	}
	// Links to the neighbor UIs for the cross-tool nav (full URL or bare
	// port; absent when running standalone).
	for envKey, hintKey := range map[string]string{
		"YARD_LINK_HOSE":   "linkHose",
		"YARD_LINK_VALVE":  "linkValve",
		"YARD_LINK_BUCKET": "linkBucket",
	} {
		if v := os.Getenv(envKey); v != "" {
			hints[hintKey] = v
		}
	}

	// External shares are mounted by the deployment under /shares/<name>;
	// YARD_SHARES lists which names to offer in the UI.
	shares := codegen.Shares{}
	if v := os.Getenv("YARD_SHARES"); v != "" {
		var ok []string
		for _, name := range strings.Split(v, ",") {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			mount := filepath.Join("/shares", name)
			if st, err := os.Stat(mount); err != nil || !st.IsDir() {
				fmt.Fprintf(os.Stderr, "syslog-valve: share %q: %s not mounted, skipping\n", name, mount)
				continue
			}
			shares[name] = mount
			ok = append(ok, name)
			fmt.Printf("syslog-valve: share %q: %s\n", name, mount)
		}
		hints["shares"] = strings.Join(ok, ",")
	}

	rotator := &rotate.Rotator{
		ConfPath:  filepath.Join(dataDir, "logrotate.conf"),
		StatePath: filepath.Join(dataDir, "logrotate.state"),
	}
	go rotator.Loop(ctx, time.Hour)

	// Yard auth: when YARD_AUTH_URL points at the bucket, its user accounts
	// guard this UI too (unset = open, standalone mode).
	guard := yardauth.New(os.Getenv("YARD_AUTH_URL"), os.Getenv("YARD_COOKIE_SECURE") == "true")
	if guard.Enabled() {
		fmt.Printf("syslog-valve: auth enforced via %s\n", os.Getenv("YARD_AUTH_URL"))
	}

	api := server.New(sup, dataDir, ui, hints, shares, rotator, tp, nd, guard)
	if _, p, err := net.SplitHostPort(addr); err == nil {
		if port, err := strconv.Atoi(p); err == nil {
			api.SetHTTPPort(port)
		}
	}
	srv := &http.Server{
		Addr:    addr,
		Handler: api,
		// Bound slow-header clients; no overall read/write timeout because
		// /api/tail is a long-lived event stream.
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
	go func() {
		fmt.Printf("syslog-valve listening on %s (data dir %s, syslog-ng %s)\n",
			addr, dataDir, sup.Version())
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "syslog-valve: %v\n", err)
			cancel()
		}
	}()

	<-ctx.Done()
	fmt.Println("syslog-valve: shutting down")
	shutCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutCancel()
	srv.Shutdown(shutCtx)
	sup.Shutdown()
}
