// Package rotate runs logrotate against the generated cache retention
// config on a fixed interval (and on demand from the API).
package rotate

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

type Rotator struct {
	ConfPath  string
	StatePath string
}

// Run executes logrotate once. A missing or empty config (no cache nodes)
// is a successful no-op.
func (r *Rotator) Run() (string, error) {
	data, err := os.ReadFile(r.ConfPath)
	if err != nil || len(strings.TrimSpace(string(data))) == 0 {
		return "no cache retention configured", nil
	}
	out, err := exec.Command("logrotate", "-s", r.StatePath, r.ConfPath).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("logrotate: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

// Loop runs logrotate every interval until ctx is cancelled.
func (r *Rotator) Loop(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := r.Run(); err != nil {
				fmt.Fprintf(os.Stderr, "syslog-valve: %v\n", err)
			}
		}
	}
}
