package preset

import (
	"fmt"
	"math/rand"
	"strings"
	"text/template"
	"text/template/parse"
	"time"
)

// Bounds on what one user-supplied template can allocate.
const (
	maxRandHex  = 1024     // longest randHex string
	maxSeqNames = 256      // distinct seq counters per renderer
	maxRendered = 64 << 10 // rendered payload; larger than any UDP datagram

	// Execution cannot be preempted, so each loop pass and template call is
	// charged its overhead plus the size of its body. The budget leaves room
	// for a loop of maxRendered passes, which is as many as can emit output.
	maxRenderCost  = 32 << 20
	stepOverhead   = 256
	maxRenderWork  = 64 << 20 // total bytes built by string helpers per render
	maxFormatSize  = 1 << 20  // largest printf result worth attempting
	fmtMaxNumber   = 1000000  // package fmt's limit on widths and precisions
	renderStepFunc = "renderStep"
)

var (
	errRenderTooLong = fmt.Errorf("rendered message exceeds %d bytes", maxRendered)
	errRenderBudget  = fmt.Errorf("template exceeded its render budget")
)

// boundTemplate makes every loop pass and template call count against the
// render budget, by adding a step action that outputs nothing.
func boundTemplate(t *template.Template) error {
	for _, tmpl := range t.Templates() {
		if tmpl.Tree == nil || tmpl.Root == nil {
			continue
		}
		cost := stepOverhead + len(tmpl.Root.String())
		if err := addRangeSteps(tmpl.Root); err != nil {
			return err
		}
		if err := prependStep(tmpl.Root, cost); err != nil {
			return err
		}
	}
	return nil
}

func addRangeSteps(list *parse.ListNode) error {
	if list == nil {
		return nil
	}
	for _, n := range list.Nodes {
		var body, alt *parse.ListNode
		cost := 0
		switch n := n.(type) {
		case *parse.IfNode:
			body, alt = n.List, n.ElseList
		case *parse.WithNode:
			body, alt = n.List, n.ElseList
		case *parse.RangeNode:
			body, alt = n.List, n.ElseList
			cost = stepOverhead + len(n.Pipe.String()) + len(body.String())
		default:
			continue
		}
		if err := addRangeSteps(body); err != nil {
			return err
		}
		if err := addRangeSteps(alt); err != nil {
			return err
		}
		if cost > 0 {
			if err := prependStep(body, cost); err != nil {
				return err
			}
		}
	}
	return nil
}

func prependStep(list *parse.ListNode, cost int) error {
	st, err := template.New("step").
		Funcs(template.FuncMap{renderStepFunc: func(int) string { return "" }}).
		Parse(fmt.Sprintf("{{%s %d}}", renderStepFunc, cost))
	if err != nil {
		return err
	}
	list.Nodes = append([]parse.Node{st.Tree.Root.Nodes[0]}, list.Nodes...)
	return nil
}

// argSize estimates the formatted size of one template argument.
func argSize(a any) int64 {
	if s, ok := a.(string); ok {
		return int64(len(s))
	}
	return 32
}

// formatBound is an upper estimate of a printf result, computed before any
// of it is allocated: widths and precisions can pad, %q and %x can expand,
// and explicit argument indexes can reuse the largest argument.
func formatBound(format string, args []any) int64 {
	var content, largest int64
	width := formatPadding(format, args)
	for _, a := range args {
		n := argSize(a)
		content += n
		largest = max(largest, n)
	}
	verbs := int64(strings.Count(format, "%"))
	if strings.Contains(format, "[") {
		content = verbs * largest
	}
	return int64(len(format)) + 6*content + verbs*(width+32)
}

// formatPadding returns the largest width or precision of any verb in format,
// following the parser in package fmt so that literal text and %% never count.
// A * may take any integer operand; fmt ignores those beyond fmtMaxNumber.
func formatPadding(format string, args []any) int64 {
	var most, star int64
	for _, a := range args {
		var v int64
		switch n := a.(type) {
		case int:
			v = int64(n)
		case int64:
			v = n
		}
		if v >= -fmtMaxNumber && v <= fmtMaxNumber {
			star = max(star, v, -v)
		}
	}
	n := len(format)
	for i := 0; i < n; {
		if format[i] != '%' {
			i++
			continue
		}
		i++
		for i < n && strings.IndexByte("#0+- ", format[i]) >= 0 {
			i++
		}
		var pad int64
		var afterIndex bool
		field := func() {
			i, afterIndex = skipArgIndex(format, i)
			if i < n && format[i] == '*' {
				i++
				pad = max(pad, star)
				afterIndex = false
				return
			}
			var v int64
			v, _, i = fmtNumber(format, i, n)
			pad = max(pad, v)
		}
		field()
		if i+1 < n && format[i] == '.' {
			i++
			field()
		}
		if !afterIndex {
			i, _ = skipArgIndex(format, i)
		}
		if i >= n {
			break
		}
		if format[i] != '%' { // %% ignores any width it was given
			most = max(most, pad)
		}
		i++
	}
	return most
}

// skipArgIndex steps over an explicit argument index such as [2] at format[i]
// and reports whether it was well formed, as fmt's parseArgNumber does.
func skipArgIndex(format string, i int) (int, bool) {
	if i >= len(format) || format[i] != '[' {
		return i, false
	}
	if len(format)-i < 3 {
		return i + 1, false
	}
	for j := i + 1; j < len(format); j++ {
		if format[j] == ']' {
			_, ok, next := fmtNumber(format, i+1, j)
			return j + 1, ok && next == j
		}
	}
	return i + 1, false
}

// fmtNumber reads a decimal from s[start:end] as fmt's parsenum does,
// including giving up and consuming the rest of s[:end] on an oversized one.
func fmtNumber(s string, start, end int) (num int64, ok bool, next int) {
	if start >= end {
		return 0, false, end
	}
	for next = start; next < end && s[next] >= '0' && s[next] <= '9'; next++ {
		if num > fmtMaxNumber {
			return 0, false, end
		}
		num = num*10 + int64(s[next]-'0')
		ok = true
	}
	return num, ok, next
}

// keep accounts for a string built by a helper and enforces the size limits.
func (c *renderContext) keep(s string) (string, error) {
	if len(s) > maxRendered {
		return "", errRenderTooLong
	}
	if c.work += len(s); c.work > maxRenderWork {
		return "", errRenderBudget
	}
	return s, nil
}

// capped wraps a variadic string builtin with the render limits.
func (c *renderContext) capped(fn func(...any) string) func(...any) (string, error) {
	return func(args ...any) (string, error) {
		var n int64
		for _, a := range args {
			n += argSize(a)
		}
		if n > maxRendered {
			return "", errRenderTooLong
		}
		return c.keep(fn(args...))
	}
}

// cappedBuffer collects template output and fails once it would grow past
// maxRendered, which aborts the template execution.
type cappedBuffer struct{ sb strings.Builder }

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.sb.Len()+len(p) > maxRendered {
		return 0, errRenderTooLong
	}
	return b.sb.Write(p)
}

func (b *cappedBuffer) String() string { return b.sb.String() }

// renderContext binds template helper functions to one event render: the
// event timestamp, the job's hostname/appname, its RNG and sequence counters.
type renderContext struct {
	preset   *Preset
	hostname string
	appname  string
	now      time.Time
	rng      *rand.Rand
	seqs     map[string]int64
	cost     int // charged by loop passes and template calls so far
	work     int // bytes built by string helpers so far
}

func newRenderContext(p *Preset, hostname string, rng *rand.Rand, seqs map[string]int64) *renderContext {
	if seqs == nil {
		seqs = map[string]int64{}
	}
	return &renderContext{preset: p, hostname: hostname, now: time.Now(), rng: rng, seqs: seqs}
}

func (c *renderContext) funcs() template.FuncMap {
	return template.FuncMap{
		renderStepFunc: func(cost int) (string, error) {
			if c.cost += cost; c.cost > maxRenderCost {
				return "", errRenderBudget
			}
			return "", nil
		},
		"print":    c.capped(fmt.Sprint),
		"println":  c.capped(fmt.Sprintln),
		"html":     c.capped(template.HTMLEscaper),
		"js":       c.capped(template.JSEscaper),
		"urlquery": c.capped(template.URLQueryEscaper),
		"printf": func(format string, args ...any) (string, error) {
			if formatBound(format, args) > maxFormatSize {
				return "", errRenderTooLong
			}
			return c.keep(fmt.Sprintf(format, args...))
		},
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
		"randHex": func(n int) (string, error) {
			const hex = "0123456789abcdef"
			n = min(n, maxRandHex) // templates come from users (preview, presets)
			var sb strings.Builder
			sb.Grow(max(n, 0))
			for i := 0; i < n; i++ {
				sb.WriteByte(hex[c.rng.Intn(16)])
			}
			return c.keep(sb.String())
		},
		"oneOf": func(opts ...string) string {
			if len(opts) == 0 {
				return ""
			}
			return opts[c.rng.Intn(len(opts))]
		},
		"seq": func(name string) int64 {
			if _, ok := c.seqs[name]; !ok {
				if len(c.seqs) >= maxSeqNames {
					// a computed name (seq (randHex 8)) would otherwise
					// grow the map for as long as the job runs
					return int64(c.rng.Intn(900000) + 100000)
				}
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
