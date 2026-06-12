// Package netclass classifies the IP addresses an entry mentions: which
// scope they fall in (RFC1918-internal, special-use, or external/public),
// which curated category sets they hit (threat-intel feeds, Microsoft 365
// ranges, admin-defined CIDR groups — see internal/netfeeds), and, when the
// message carries recognisable src/dst fields, which way the traffic was
// going. It is the network counterpart of internal/mitre and
// internal/otmap, but unlike those it runs at read time: feed updates then
// flag historical entries too, without restamping rows.
package netclass

import (
	"net/netip"
	"regexp"
	"sort"
	"strings"
)

// Scopes (every address gets exactly one).
const (
	ScopeInternal = "internal" // RFC1918, ULA — the org's own ranges
	ScopeSpecial  = "special"  // loopback, link-local, CGNAT, multicast, …
	ScopeExternal = "external" // everything else: the public internet
)

// Directions (per entry, when src and dst could both be parsed).
const (
	DirInbound  = "inbound"  // external → internal
	DirOutbound = "outbound" // internal → external
	DirInternal = "internal" // internal → internal (lateral)
	DirExternal = "external" // external → external (observed transit)
	DirUnknown  = "unknown"  // no parseable src/dst pair
)

// IPs is what Extract finds in one entry.
type IPs struct {
	Src, Dst netip.Addr   // zero value = not identified
	All      []netip.Addr // de-duplicated, includes Src/Dst and the host field
}

// Result is the classification of one entry.
type Result struct {
	Direction string
	Scopes    []string            // unique scopes present among All
	Hits      map[string][]string // category set name → matched addresses
}

// kv fields that name the two ends of a flow. Covers the common firewall
// syntaxes: FortiGate (srcip=/dstip=), CEF (src=/dst=), iptables (SRC=/DST=),
// plus generic from=/to=.
var (
	srcRe = regexp.MustCompile(`(?i)\b(?:srcip|src|source|from)=\[?([0-9a-f.:]+)`)
	dstRe = regexp.MustCompile(`(?i)\b(?:dstip|dst|destination|to)=\[?([0-9a-f.:]+)`)
	// Bare addresses anywhere in the text. The IPv6 arms only gather
	// candidates — compressed (has ::) or full 8-group — and ParseAddr
	// rejects look-alikes (times, MACs). Times like 12:30:01 never match.
	ipRe = regexp.MustCompile(`\b\d{1,3}(?:\.\d{1,3}){3}\b|[0-9a-fA-F:]*::[0-9a-fA-F:.]*|\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b`)
)

func parseAddr(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(strings.TrimSuffix(s, "."))
	if err != nil || !a.IsValid() {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

// Extract pulls the addresses out of an entry's host field and message.
func Extract(host, msg string) IPs {
	var out IPs
	seen := map[netip.Addr]bool{}
	add := func(a netip.Addr) {
		if !seen[a] {
			seen[a] = true
			out.All = append(out.All, a)
		}
	}
	if m := srcRe.FindStringSubmatch(msg); m != nil {
		if a, ok := parseAddr(m[1]); ok {
			out.Src = a
			add(a)
		}
	}
	if m := dstRe.FindStringSubmatch(msg); m != nil {
		if a, ok := parseAddr(m[1]); ok {
			out.Dst = a
			add(a)
		}
	}
	for _, raw := range ipRe.FindAllString(msg, 16) {
		if raw == "::" { // bare :: is more likely punctuation than ANY-addr
			continue
		}
		if a, ok := parseAddr(raw); ok {
			add(a)
		}
	}
	if a, ok := parseAddr(host); ok {
		add(a)
	}
	return out
}

// rfc1918 + ULA: ranges an org owns; specials are non-routable or reserved.
var (
	internalPrefixes = parsePrefixes(
		"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", // RFC1918
		"fc00::/7", // IPv6 ULA
	)
	specialPrefixes = parsePrefixes(
		"127.0.0.0/8", "::1/128", // loopback
		"169.254.0.0/16", "fe80::/10", // link-local
		"100.64.0.0/10",                // CGNAT
		"224.0.0.0/4", "ff00::/8",      // multicast
		"0.0.0.0/8", "::/128",          // unspecified
		"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", // TEST-NET
		"255.255.255.255/32",
	)
)

func parsePrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

// Scope buckets one address: internal, special, or external.
func Scope(a netip.Addr) string {
	for _, p := range internalPrefixes {
		if p.Contains(a) {
			return ScopeInternal
		}
	}
	for _, p := range specialPrefixes {
		if p.Contains(a) {
			return ScopeSpecial
		}
	}
	return ScopeExternal
}

// Set is a named, immutable group of CIDR ranges (one threat feed, the O365
// ranges, or an admin-defined category), compiled for fast lookups: ranges
// are sorted by start address and probed with a binary search.
type Set struct {
	Name   string
	ranges []ipRange
}

type ipRange struct{ first, last netip.Addr }

// NewSet compiles prefixes into a Set. Mixed v4/v6 is fine.
func NewSet(name string, prefixes []netip.Prefix) *Set {
	rs := make([]ipRange, 0, len(prefixes))
	for _, p := range prefixes {
		rs = append(rs, ipRange{first: p.Masked().Addr(), last: lastAddr(p)})
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].first.Less(rs[j].first) })
	return &Set{Name: name, ranges: rs}
}

func (s *Set) Len() int { return len(s.ranges) }

// Contains reports whether a falls in any of the set's ranges.
func (s *Set) Contains(a netip.Addr) bool {
	// Rightmost range starting at or before a.
	lo, hi := 0, len(s.ranges)
	for lo < hi {
		mid := (lo + hi) / 2
		if s.ranges[mid].first.Compare(a) <= 0 {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	return lo > 0 && s.ranges[lo-1].last.Compare(a) >= 0
}

// lastAddr is the highest address inside p (host bits all set).
func lastAddr(p netip.Prefix) netip.Addr {
	bytes := p.Masked().Addr().As16()
	bits := p.Bits()
	if p.Addr().Is4() {
		bits += 96 // host bits count from the v4-mapped position
	}
	for i := bits; i < 128; i++ {
		bytes[i/8] |= 1 << (7 - i%8)
	}
	a := netip.AddrFrom16(bytes)
	if p.Addr().Is4() {
		return a.Unmap()
	}
	return a
}

// Classify scopes the extracted addresses, derives the flow direction, and
// matches every address against the given category sets.
func Classify(ips IPs, sets []*Set) Result {
	res := Result{Direction: DirUnknown, Hits: map[string][]string{}}
	seenScope := map[string]bool{}
	for _, a := range ips.All {
		if sc := Scope(a); !seenScope[sc] {
			seenScope[sc] = true
			res.Scopes = append(res.Scopes, sc)
		}
		for _, set := range sets {
			if set.Contains(a) {
				res.Hits[set.Name] = append(res.Hits[set.Name], a.String())
			}
		}
	}
	sort.Strings(res.Scopes)
	if ips.Src.IsValid() && ips.Dst.IsValid() {
		s, d := Scope(ips.Src), Scope(ips.Dst)
		switch {
		case s == ScopeInternal && d == ScopeExternal:
			res.Direction = DirOutbound
		case s == ScopeExternal && d == ScopeInternal:
			res.Direction = DirInbound
		case s == ScopeInternal && d == ScopeInternal:
			res.Direction = DirInternal
		case s == ScopeExternal && d == ScopeExternal:
			res.Direction = DirExternal
		}
	}
	return res
}
