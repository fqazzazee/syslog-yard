// Package netfeeds maintains the CIDR category sets the network view
// classifies against: online threat-intel databases (Spamhaus DROP, abuse.ch
// Feodo Tracker C2s, Tor exit nodes), the Microsoft 365 endpoint ranges, and
// admin-defined custom categories. Feeds are fetched periodically; the last
// good snapshot is cached in app_settings so classification keeps working
// across restarts and offline spells. Matching itself lives in
// internal/netclass — this package just keeps the compiled sets fresh.
package netfeeds

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/syslog-yard/syslog-bucket/internal/netclass"
	"github.com/syslog-yard/syslog-bucket/internal/store"
)

const (
	refreshEvery = 12 * time.Hour
	fetchTimeout = 30 * time.Second
	maxBody      = 16 << 20 // generous: the O365 endpoint doc is ~1MB
	configKey    = "net.config"
	feedKeyPfx   = "net.feed." // + feed id → cached snapshot
)

// Categories group sets in the UI. CatMalicious is the one the view flags.
const (
	CatMalicious = "malicious"
	CatTor       = "tor"
	CatO365      = "o365"
	CatCustom    = "custom"
)

// feedDef is one built-in online database.
type feedDef struct {
	ID       string
	Label    string
	Category string
	URL      string
	Parse    func([]byte) ([]netip.Prefix, error)
}

var builtins = []feedDef{
	{
		ID: "spamhaus_drop", Label: "Spamhaus DROP", Category: CatMalicious,
		URL:   "https://www.spamhaus.org/drop/drop_v4.json",
		Parse: parseSpamhausDrop,
	},
	{
		ID: "feodo_c2", Label: "Feodo Tracker C2 (abuse.ch)", Category: CatMalicious,
		URL:   "https://feodotracker.abuse.ch/downloads/ipblocklist.json",
		Parse: parseFeodo,
	},
	{
		ID: "tor_exits", Label: "Tor exit nodes", Category: CatTor,
		URL:   "https://check.torproject.org/torbulkexitlist",
		Parse: parsePlainIPs,
	},
	{
		ID: "o365", Label: "Microsoft 365 endpoints", Category: CatO365,
		URL:   "https://endpoints.office.com/endpoints/worldwide?clientrequestid=" + requestID(),
		Parse: parseO365,
	},
}

// Config is the admin-editable document at app_settings net.config.
type Config struct {
	Feeds  map[string]bool `json:"feeds"`  // feed id → enabled
	Custom []CustomCat     `json:"custom"` // admin-defined CIDR categories
}

// CustomCat is an org-defined matcher: a name plus its CIDRs (bare IPs ok).
type CustomCat struct {
	Name  string   `json:"name"`
	CIDRs []string `json:"cidrs"`
}

// DefaultConfig enables every built-in feed.
func DefaultConfig() Config {
	c := Config{Feeds: map[string]bool{}}
	for _, f := range builtins {
		c.Feeds[f.ID] = true
	}
	return c
}

// snapshot is the cached fetch result for one feed.
type snapshot struct {
	FetchedAt   time.Time `json:"fetched_at"`
	Prefixes    []string  `json:"prefixes"`
	LastAttempt time.Time `json:"last_attempt,omitempty"`
	LastError   string    `json:"last_error,omitempty"`
}

// Status is one row of the UI's feed table.
type Status struct {
	ID        string    `json:"id"`
	Label     string    `json:"label"`
	Category  string    `json:"category"`
	Enabled   bool      `json:"enabled"`
	Prefixes  int       `json:"prefixes"`
	FetchedAt time.Time `json:"fetched_at"`
	Error     string    `json:"error,omitempty"`
}

// SetInfo describes one compiled set so the API can attribute hits.
type SetInfo struct {
	ID       string `json:"id"`
	Label    string `json:"label"`
	Category string `json:"category"`
}

type Manager struct {
	store  *store.Store
	client *http.Client

	mu     sync.RWMutex
	config Config
	snaps  map[string]snapshot
	sets   []*netclass.Set    // compiled, set Name == feed/custom id
	info   map[string]SetInfo // id → metadata
}

func New(st *store.Store) *Manager {
	return &Manager{
		store:  st,
		client: &http.Client{Timeout: fetchTimeout},
		config: DefaultConfig(),
		snaps:  map[string]snapshot{},
		info:   map[string]SetInfo{},
	}
}

// Load restores the stored config and feed snapshots, then compiles the
// sets. Call once at startup, before Run.
func (m *Manager) Load(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if raw, ok, err := m.store.GetSetting(ctx, configKey); err == nil && ok {
		var c Config
		if json.Unmarshal(raw, &c) == nil {
			m.config = withDefaults(c)
		}
	}
	for _, f := range builtins {
		if raw, ok, err := m.store.GetSetting(ctx, feedKeyPfx+f.ID); err == nil && ok {
			var sn snapshot
			if json.Unmarshal(raw, &sn) == nil {
				m.snaps[f.ID] = sn
			}
		}
	}
	m.compileLocked()
}

// withDefaults fills feed switches a stored config predates.
func withDefaults(c Config) Config {
	if c.Feeds == nil {
		c.Feeds = map[string]bool{}
	}
	for _, f := range builtins {
		if _, ok := c.Feeds[f.ID]; !ok {
			c.Feeds[f.ID] = true
		}
	}
	return c
}

// Run refreshes stale feeds immediately and then on a ticker, until ctx ends.
func (m *Manager) Run(ctx context.Context) {
	m.RefreshStale(ctx)
	t := time.NewTicker(refreshEvery)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			m.RefreshStale(ctx)
		case <-ctx.Done():
			return
		}
	}
}

// RefreshStale fetches every enabled feed whose snapshot is older than the
// refresh interval (or missing).
func (m *Manager) RefreshStale(ctx context.Context) {
	m.mu.RLock()
	cfg := m.config
	stale := make([]feedDef, 0, len(builtins))
	for _, f := range builtins {
		if cfg.Feeds[f.ID] && time.Since(m.snaps[f.ID].FetchedAt) > refreshEvery {
			stale = append(stale, f)
		}
	}
	m.mu.RUnlock()
	m.refresh(ctx, stale)
}

// RefreshAll force-fetches every enabled feed (the admin's "refresh now").
func (m *Manager) RefreshAll(ctx context.Context) {
	m.mu.RLock()
	cfg := m.config
	all := make([]feedDef, 0, len(builtins))
	for _, f := range builtins {
		if cfg.Feeds[f.ID] {
			all = append(all, f)
		}
	}
	m.mu.RUnlock()
	m.refresh(ctx, all)
}

func (m *Manager) refresh(ctx context.Context, feeds []feedDef) {
	for _, f := range feeds {
		prefixes, err := m.fetch(ctx, f)
		m.mu.Lock()
		sn := m.snaps[f.ID]
		sn.LastAttempt = time.Now().UTC()
		if err != nil {
			sn.LastError = err.Error()
			slog.Warn("netfeeds: fetch failed", "feed", f.ID, "error", err)
		} else {
			sn.LastError = ""
			sn.FetchedAt = sn.LastAttempt
			sn.Prefixes = prefixes
			slog.Info("netfeeds: refreshed", "feed", f.ID, "prefixes", len(prefixes))
		}
		m.snaps[f.ID] = sn
		m.compileLocked()
		m.mu.Unlock()
		// Persist outside the lock; the snapshot is value-copied above.
		if err := m.store.PutSetting(ctx, feedKeyPfx+f.ID, sn); err != nil {
			slog.Warn("netfeeds: cache snapshot", "feed", f.ID, "error", err)
		}
	}
}

func (m *Manager) fetch(ctx context.Context, f feedDef) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.URL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "syslog-bucket-netfeeds/1.0")
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered %s", f.URL, resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, err
	}
	prefixes, err := f.Parse(body)
	if err != nil {
		return nil, err
	}
	if len(prefixes) == 0 {
		return nil, fmt.Errorf("feed parsed to zero prefixes (format change?)")
	}
	out := make([]string, len(prefixes))
	for i, p := range prefixes {
		out[i] = p.String()
	}
	sort.Strings(out)
	return out, nil
}

// Config returns a deep-enough copy of the current config. Custom is always
// non-nil so the API marshals [] (not null) — the UI maps over it.
func (m *Manager) Config() Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c := Config{Feeds: map[string]bool{}, Custom: make([]CustomCat, 0, len(m.config.Custom))}
	c.Custom = append(c.Custom, m.config.Custom...)
	for k, v := range m.config.Feeds {
		c.Feeds[k] = v
	}
	return c
}

// SetConfig validates, stores, and applies a new config. Newly enabled feeds
// are fetched by the caller via RefreshStale (their snapshots are stale or
// missing by definition).
func (m *Manager) SetConfig(ctx context.Context, c Config) error {
	c = withDefaults(c)
	seen := map[string]bool{}
	for i, cc := range c.Custom {
		name := strings.TrimSpace(cc.Name)
		if name == "" {
			return fmt.Errorf("custom category %d: name is required", i+1)
		}
		if seen[strings.ToLower(name)] {
			return fmt.Errorf("custom category %q: duplicate name", name)
		}
		seen[strings.ToLower(name)] = true
		if _, err := parseCIDRList(cc.CIDRs); err != nil {
			return fmt.Errorf("custom category %q: %w", name, err)
		}
		c.Custom[i].Name = name
	}
	if err := m.store.PutSetting(ctx, configKey, c); err != nil {
		return err
	}
	m.mu.Lock()
	m.config = c
	m.compileLocked()
	m.mu.Unlock()
	return nil
}

// Sets returns the compiled category sets plus their metadata. The slice is
// rebuilt on every config/feed change, never mutated — safe to use without
// holding the lock.
func (m *Manager) Sets() ([]*netclass.Set, map[string]SetInfo) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.sets, m.info
}

// Statuses reports every built-in feed (for the UI's feeds table).
func (m *Manager) Statuses() []Status {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Status, 0, len(builtins))
	for _, f := range builtins {
		sn := m.snaps[f.ID]
		out = append(out, Status{
			ID: f.ID, Label: f.Label, Category: f.Category,
			Enabled: m.config.Feeds[f.ID], Prefixes: len(sn.Prefixes),
			FetchedAt: sn.FetchedAt, Error: sn.LastError,
		})
	}
	return out
}

// compileLocked rebuilds the netclass sets from enabled feeds + custom
// categories. Caller holds m.mu.
func (m *Manager) compileLocked() {
	sets := make([]*netclass.Set, 0, len(builtins)+len(m.config.Custom))
	info := map[string]SetInfo{}
	for _, f := range builtins {
		if !m.config.Feeds[f.ID] {
			continue
		}
		prefixes, _ := parseCIDRList(m.snaps[f.ID].Prefixes)
		sets = append(sets, netclass.NewSet(f.ID, prefixes))
		info[f.ID] = SetInfo{ID: f.ID, Label: f.Label, Category: f.Category}
	}
	for i, cc := range m.config.Custom {
		id := fmt.Sprintf("custom_%d", i)
		prefixes, _ := parseCIDRList(cc.CIDRs)
		sets = append(sets, netclass.NewSet(id, prefixes))
		info[id] = SetInfo{ID: id, Label: cc.Name, Category: CatCustom}
	}
	m.sets = sets
	m.info = info
}

// parseCIDRList accepts CIDRs and bare addresses (→ /32 or /128).
func parseCIDRList(ss []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p)
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("not an IP or CIDR: %q", s)
		}
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

// --- feed format parsers ---

// parseSpamhausDrop reads Spamhaus DROP's JSON-lines: one {"cidr": "..."}
// object per line, plus a trailing summary record without a cidr.
func parseSpamhausDrop(body []byte) ([]netip.Prefix, error) {
	var out []netip.Prefix
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec struct {
			CIDR string `json:"cidr"`
		}
		if json.Unmarshal(line, &rec) != nil || rec.CIDR == "" {
			continue
		}
		if p, err := netip.ParsePrefix(rec.CIDR); err == nil {
			out = append(out, p)
		}
	}
	return out, sc.Err()
}

// parseFeodo reads abuse.ch Feodo Tracker's JSON array of C2 records.
func parseFeodo(body []byte) ([]netip.Prefix, error) {
	var recs []struct {
		IPAddress string `json:"ip_address"`
	}
	if err := json.Unmarshal(body, &recs); err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for _, r := range recs {
		if a, err := netip.ParseAddr(r.IPAddress); err == nil {
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out, nil
}

// parsePlainIPs reads one address per line (the Tor exit list format).
func parsePlainIPs(body []byte) ([]netip.Prefix, error) {
	var out []netip.Prefix
	sc := bufio.NewScanner(bytes.NewReader(body))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if a, err := netip.ParseAddr(line); err == nil {
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out, sc.Err()
}

// parseO365 reads Microsoft's endpoints document: an array of service areas,
// each carrying an "ips" list of CIDRs (v4 and v6, with duplicates).
func parseO365(body []byte) ([]netip.Prefix, error) {
	var areas []struct {
		IPs []string `json:"ips"`
	}
	if err := json.Unmarshal(body, &areas); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var out []netip.Prefix
	for _, a := range areas {
		for _, s := range a.IPs {
			if seen[s] {
				continue
			}
			seen[s] = true
			if p, err := netip.ParsePrefix(s); err == nil {
				out = append(out, p)
			}
		}
	}
	return out, nil
}

// requestID is the random client id Microsoft's endpoint API requires.
func requestID() string {
	var b [16]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:4]) + "-" + hex.EncodeToString(b[4:6]) + "-" +
		hex.EncodeToString(b[6:8]) + "-" + hex.EncodeToString(b[8:10]) + "-" + hex.EncodeToString(b[10:])
}
