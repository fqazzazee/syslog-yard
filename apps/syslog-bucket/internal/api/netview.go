package api

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/syslog-yard/syslog-bucket/internal/netclass"
	"github.com/syslog-yard/syslog-bucket/internal/netfeeds"
	"github.com/syslog-yard/syslog-bucket/internal/store"
)

// The network security view: entries are scanned over a recent window, their
// addresses extracted and classified (internal/netclass) against the live
// category sets (internal/netfeeds). Read-time classification means a threat
// feed update retroactively flags matching history — nothing is restamped.

const (
	netDefaultMinutes = 24 * 60
	netMaxMinutes     = 7 * 24 * 60
	netScanCap        = 20000 // rows per classification pass
	netSummaryTTL     = 15 * time.Second
	netTopIPs         = 50  // malicious IPs listed in the summary
	netDrillLimit     = 200 // entries returned per drill-down
	netSampleIDs      = 5   // sample entry ids per flagged IP
)

// netSummaryCache memoizes the latest summary per window so a polling UI
// doesn't rescan on every request.
type netSummaryCache struct {
	mu  sync.Mutex
	key string
	at  time.Time
	val map[string]any
}

type netIPHit struct {
	IP       string   `json:"ip"`
	Feeds    []string `json:"feeds"` // set ids that flagged it
	Count    int      `json:"count"` // entries it appeared in
	LastSeen string   `json:"last_seen"`
	EntryIDs []int64  `json:"entry_ids"` // newest few, for drill-down
}

func netMinutes(r *http.Request) int {
	m, _ := strconv.Atoi(r.URL.Query().Get("minutes"))
	if m <= 0 {
		m = netDefaultMinutes
	}
	if m > netMaxMinutes {
		m = netMaxMinutes
	}
	return m
}

// netScan loads the window and classifies every row. The callback sees each
// row with its extracted addresses and classification.
func (s *server) netScan(r *http.Request, minutes int, visit func(row store.NetScanRow, ips netclass.IPs, res netclass.Result)) (scanned int, truncated bool, err error) {
	since := time.Now().Add(-time.Duration(minutes) * time.Minute)
	rows, err := s.store.NetScan(r.Context(), since, netScanCap)
	if err != nil {
		return 0, false, err
	}
	sets, _ := s.netMgr.Sets()
	for _, row := range rows {
		ips := netclass.Extract(row.Host, row.Msg)
		visit(row, ips, netclass.Classify(ips, sets))
	}
	return len(rows), len(rows) == netScanCap, nil
}

func (s *server) getNetSummary(w http.ResponseWriter, r *http.Request) {
	minutes := netMinutes(r)
	key := strconv.Itoa(minutes)
	s.netSum.mu.Lock()
	if s.netSum.key == key && time.Since(s.netSum.at) < netSummaryTTL {
		val := s.netSum.val
		s.netSum.mu.Unlock()
		writeJSON(w, val)
		return
	}
	s.netSum.mu.Unlock()

	_, infos := s.netMgr.Sets()
	directions := map[string]int{}
	scopes := map[string]int{}
	setCounts := map[string]int{}
	type ipAgg struct {
		feeds map[string]bool
		count int
		last  time.Time
		ids   []int64
	}
	malicious := map[string]*ipAgg{}

	scanned, truncated, err := s.netScan(r, minutes, func(row store.NetScanRow, ips netclass.IPs, res netclass.Result) {
		if len(ips.All) == 0 {
			return
		}
		directions[res.Direction]++
		for _, sc := range res.Scopes {
			scopes[sc]++
		}
		for setID, addrs := range res.Hits {
			setCounts[setID]++
			if infos[setID].Category != netfeeds.CatMalicious {
				continue
			}
			for _, ip := range addrs {
				agg := malicious[ip]
				if agg == nil {
					agg = &ipAgg{feeds: map[string]bool{}}
					malicious[ip] = agg
				}
				agg.feeds[setID] = true
				agg.count++
				if row.ReceivedAt.After(agg.last) {
					agg.last = row.ReceivedAt
				}
				if len(agg.ids) < netSampleIDs {
					agg.ids = append(agg.ids, row.ID) // rows arrive newest first
				}
			}
		}
	})
	if err != nil {
		s.internalError(w, "net summary", err)
		return
	}

	cats := make([]map[string]any, 0, len(infos))
	for id, info := range infos {
		cats = append(cats, map[string]any{
			"id": id, "label": info.Label, "category": info.Category,
			"count": setCounts[id],
		})
	}
	sort.Slice(cats, func(i, j int) bool { return cats[i]["id"].(string) < cats[j]["id"].(string) })

	hits := make([]netIPHit, 0, len(malicious))
	for ip, agg := range malicious {
		feeds := make([]string, 0, len(agg.feeds))
		for f := range agg.feeds {
			feeds = append(feeds, f)
		}
		sort.Strings(feeds)
		hits = append(hits, netIPHit{
			IP: ip, Feeds: feeds, Count: agg.count,
			LastSeen: agg.last.UTC().Format(time.RFC3339), EntryIDs: agg.ids,
		})
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].Count != hits[j].Count {
			return hits[i].Count > hits[j].Count
		}
		return hits[i].IP < hits[j].IP
	})
	if len(hits) > netTopIPs {
		hits = hits[:netTopIPs]
	}

	val := map[string]any{
		"window_minutes": minutes,
		"scanned":        scanned,
		"truncated":      truncated,
		"directions":     directions,
		"scopes":         scopes,
		"categories":     cats,
		"malicious":      hits,
		"feeds":          s.netMgr.Statuses(),
	}
	s.netSum.mu.Lock()
	s.netSum.key, s.netSum.at, s.netSum.val = key, time.Now(), val
	s.netSum.mu.Unlock()
	writeJSON(w, val)
}

// getNetEntries drills into one class: dir:<direction>, scope:<scope>,
// set:<set id>, or the shorthand "malicious" (any malicious-category set).
func (s *server) getNetEntries(w http.ResponseWriter, r *http.Request) {
	class := r.URL.Query().Get("class")
	ip := r.URL.Query().Get("ip") // optional: narrow to one address
	if class == "" && ip == "" {
		http.Error(w, "class or ip parameter is required", http.StatusBadRequest)
		return
	}
	_, infos := s.netMgr.Sets()
	match := func(ips netclass.IPs, res netclass.Result) bool {
		if ip != "" {
			found := false
			for _, a := range ips.All {
				if a.String() == ip {
					found = true
					break
				}
			}
			if !found {
				return false
			}
		}
		switch {
		case class == "":
			return true
		case class == "malicious":
			for setID := range res.Hits {
				if infos[setID].Category == netfeeds.CatMalicious {
					return true
				}
			}
			return false
		case strings.HasPrefix(class, "dir:"):
			return res.Direction == class[len("dir:"):]
		case strings.HasPrefix(class, "scope:"):
			want := class[len("scope:"):]
			for _, sc := range res.Scopes {
				if sc == want {
					return true
				}
			}
			return false
		case strings.HasPrefix(class, "set:"):
			_, ok := res.Hits[class[len("set:"):]]
			return ok
		}
		return false
	}

	var ids []int64
	_, _, err := s.netScan(r, netMinutes(r), func(row store.NetScanRow, ips netclass.IPs, res netclass.Result) {
		if len(ids) < netDrillLimit && match(ips, res) {
			ids = append(ids, row.ID)
		}
	})
	if err != nil {
		s.internalError(w, "net entries", err)
		return
	}
	entries, err := s.store.EntriesByIDs(r.Context(), ids)
	if err != nil {
		s.internalError(w, "net entries", err)
		return
	}
	writeJSON(w, map[string]any{"entries": entries})
}

func (s *server) getNetConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{
		"config": s.netMgr.Config(),
		"feeds":  s.netMgr.Statuses(),
	})
}

func (s *server) putNetConfig(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	var in netfeeds.Config
	if !decodeJSON(w, r, &in) {
		return
	}
	if err := s.netMgr.SetConfig(r.Context(), in); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Newly enabled feeds have stale (or no) snapshots — fetch them now so
	// the save gives immediate feedback.
	s.netMgr.RefreshStale(r.Context())
	s.netSum.mu.Lock()
	s.netSum.key = "" // drop the cached summary; sets just changed
	s.netSum.mu.Unlock()
	writeJSON(w, map[string]any{"ok": true, "feeds": s.netMgr.Statuses()})
}

func (s *server) refreshNetFeeds(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	s.netMgr.RefreshAll(r.Context())
	s.netSum.mu.Lock()
	s.netSum.key = ""
	s.netSum.mu.Unlock()
	writeJSON(w, map[string]any{"ok": true, "feeds": s.netMgr.Statuses()})
}
