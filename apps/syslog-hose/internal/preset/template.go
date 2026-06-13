package preset

import (
	"fmt"
	"math/rand"
	"strings"
	"text/template"
	"time"
)

// renderContext binds template helper functions to one event render: the
// event timestamp, the job's hostname/appname, its RNG and sequence counters.
type renderContext struct {
	preset   *Preset
	hostname string
	appname  string
	now      time.Time
	rng      *rand.Rand
	seqs     map[string]int64
}

func newRenderContext(p *Preset, hostname string, rng *rand.Rand, seqs map[string]int64) *renderContext {
	if seqs == nil {
		seqs = map[string]int64{}
	}
	return &renderContext{preset: p, hostname: hostname, now: time.Now(), rng: rng, seqs: seqs}
}

func (c *renderContext) funcs() template.FuncMap {
	return template.FuncMap{
		"now":      func(layout string) string { return c.now.Format(layout) },
		"hostname": func() string { return c.hostname },
		"appname":  func() string { return c.appname },
		"randIP":   c.randIP,
		"randPort": func() int { return c.rng.Intn(64511) + 1024 },
		"randMAC": func() string {
			b := make([]byte, 6)
			c.rng.Read(b)
			b[0] = (b[0] | 2) & 0xfe // locally administered, unicast
			return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
		},
		"randInt": func(lo, hi int) int {
			if hi <= lo {
				return lo
			}
			return lo + c.rng.Intn(hi-lo+1)
		},
		"randHex": func(n int) string {
			const hex = "0123456789abcdef"
			var sb strings.Builder
			for i := 0; i < n; i++ {
				sb.WriteByte(hex[c.rng.Intn(16)])
			}
			return sb.String()
		},
		"oneOf": func(opts ...string) string {
			if len(opts) == 0 {
				return ""
			}
			return opts[c.rng.Intn(len(opts))]
		},
		"seq": func(name string) int64 {
			if _, ok := c.seqs[name]; !ok {
				c.seqs[name] = int64(c.rng.Intn(900000) + 100000)
			}
			c.seqs[name]++
			return c.seqs[name]
		},
		"uuid": func() string {
			b := make([]byte, 16)
			c.rng.Read(b)
			b[6] = (b[6] & 0x0f) | 0x40
			b[8] = (b[8] & 0x3f) | 0x80
			return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
		},
	}
}

// randIP returns a plausible IP. kind: "rfc1918" (private), "public", "any".
func (c *renderContext) randIP(kind string) string {
	switch kind {
	case "rfc1918":
		switch c.rng.Intn(3) {
		case 0:
			return fmt.Sprintf("10.%d.%d.%d", c.rng.Intn(256), c.rng.Intn(256), c.rng.Intn(254)+1)
		case 1:
			return fmt.Sprintf("172.%d.%d.%d", c.rng.Intn(16)+16, c.rng.Intn(256), c.rng.Intn(254)+1)
		default:
			return fmt.Sprintf("192.168.%d.%d", c.rng.Intn(256), c.rng.Intn(254)+1)
		}
	case "public":
		// Sample from blocks that read as real internet space. Deliberately
		// avoids first octets with big Microsoft allocations (13, 52, 104):
		// the bucket's network view matches real O365 ranges, and random
		// demo IPs shouldn't land in them.
		firsts := []int{8, 23, 31, 34, 45, 64, 74, 77, 91, 121, 128, 142, 151, 162, 185, 195, 203, 209}
		return fmt.Sprintf("%d.%d.%d.%d",
			firsts[c.rng.Intn(len(firsts))], c.rng.Intn(256), c.rng.Intn(256), c.rng.Intn(254)+1)
	default:
		if c.rng.Intn(2) == 0 {
			return c.randIP("rfc1918")
		}
		return c.randIP("public")
	}
}
