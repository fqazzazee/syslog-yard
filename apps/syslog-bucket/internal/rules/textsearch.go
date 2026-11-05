package rules

import (
	"strings"
	"unicode"
)

// In-memory counterpart of the SQL text condition
//
//	e.msg_tsv @@ websearch_to_tsquery('simple', <text>)
//
// where msg_tsv is to_tsvector('simple', msg). Matching is on whole lexemes,
// not substrings, and the query grammar follows websearch_to_tsquery: bare
// words are ANDed, "quoted text" is a phrase (adjacent lexemes), `or` between
// terms is OR (binding looser than AND), and a leading `-` negates a term.
//
// lexemes approximates Postgres's default text-search parser closely enough
// for log text — words, numbers, IPv4 addresses and versions, host names,
// e-mail addresses, file paths, hyphenated compounds — and the parity tests
// pin the behaviour against a real server. Exotic inputs (URLs with query
// strings, timestamps with fractional seconds, …) can still tokenize slightly
// differently.

// textMatch reports whether msg matches a websearch-syntax query the way
// Postgres would.
func textMatch(msg, query string) bool {
	groups := parseWebsearch(query)
	if len(groups) == 0 {
		return false // Postgres: a query with no lexemes matches nothing
	}
	lex := lexemes(msg)
	for _, g := range groups {
		ok := true
		for _, t := range g {
			if containsSeq(lex, t.seq) == t.neg {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// wsTerm is one query operand: a lexeme sequence that must appear
// contiguously (a single word yields a one-element sequence unless the parser
// splits it), possibly negated.
type wsTerm struct {
	seq []string
	neg bool
}

// isWebsearchSep reports the characters websearch_to_tsquery treats as plain
// separators between words (tsquery operator characters).
func isWebsearchSep(r byte) bool {
	switch r {
	case ' ', '\t', '\n', '\r', '\f', '\v', '!', '&', '|', '(', ')', ':', '<':
		return true
	}
	return false
}

// parseWebsearch returns the query as OR-groups of ANDed terms.
func parseWebsearch(q string) [][]wsTerm {
	type item struct {
		text   string
		phrase bool
		neg    int
	}
	var items []item
	neg := 0
	for i := 0; i < len(q); {
		c := q[i]
		switch {
		case isWebsearchSep(c):
			i++
		case c == '"':
			end := strings.IndexByte(q[i+1:], '"')
			var text string
			if end < 0 {
				text, i = q[i+1:], len(q)
			} else {
				text, i = q[i+1:i+1+end], i+end+2
			}
			items = append(items, item{text: text, phrase: true, neg: neg})
			neg = 0
		case c == '-':
			neg++
			i++
		default:
			j := i
			for j < len(q) && !isWebsearchSep(q[j]) && q[j] != '"' {
				j++
			}
			items = append(items, item{text: q[i:j], neg: neg})
			neg = 0
			i = j
		}
	}

	// Resolve terms; operands without lexemes vanish (Postgres ignores them).
	type resolved struct {
		term wsTerm
		isOr bool // bare `or` word, operator candidate
	}
	var rs []resolved
	for _, it := range items {
		seq := lexemes(it.text)
		if len(seq) == 0 {
			continue
		}
		rs = append(rs, resolved{
			term: wsTerm{seq: seq, neg: it.neg%2 == 1},
			isOr: !it.phrase && it.neg == 0 && strings.EqualFold(it.text, "or"),
		})
	}

	var groups [][]wsTerm
	var cur []wsTerm
	prevWasOr := false
	for i, r := range rs {
		// `or` is an operator only between two operands: not first, not
		// last, and not right after another `or` operator.
		if r.isOr && len(cur) > 0 && !prevWasOr && i < len(rs)-1 {
			groups = append(groups, cur)
			cur = nil
			prevWasOr = true
			continue
		}
		cur = append(cur, r.term)
		prevWasOr = false
	}
	if len(cur) > 0 {
		groups = append(groups, cur)
	}
	return groups
}

func containsSeq(hay, seq []string) bool {
	for i := 0; i+len(seq) <= len(hay); i++ {
		match := true
		for j, s := range seq {
			if hay[i+j] != s {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// isChunkRune reports characters that can belong to a compound token
// (host names, paths, e-mail addresses, hyphenated words).
func isChunkRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '-' || r == '/' || r == '@' || r == '_'
}

// lexemes splits text into lowercase lexemes in order, approximating
// to_tsvector('simple', text).
func lexemes(text string) []string {
	var out []string
	runes := []rune(text)
	for i := 0; i < len(runes); {
		if !isChunkRune(runes[i]) {
			i++
			continue
		}
		j := i
		for j < len(runes) && isChunkRune(runes[j]) {
			j++
		}
		chunk := string(runes[i:j])
		// A URL scheme ("https://"): Postgres drops the protocol token and
		// parses the remainder as a URL.
		if j+2 < len(runes) && runes[j] == ':' && runes[j+1] == '/' && runes[j+2] == '/' && isAlpha(chunk) {
			k := j + 3
			for k < len(runes) && isChunkRune(runes[k]) {
				k++
			}
			out = append(out, chunkLexemes(string(runes[j+3:k]))...)
			i = k
			continue
		}
		// host:port (and user@host:port) stays one lexeme, as does a URL
		// path after it.
		if j+1 < len(runes) && runes[j] == ':' && isASCIIDigit(runes[j+1]) && hostLike(chunk) {
			k := j + 1
			for k < len(runes) && isASCIIDigit(runes[k]) {
				k++
			}
			if k < len(runes) && runes[k] == '/' {
				for k < len(runes) && isChunkRune(runes[k]) {
					k++
				}
			}
			out = append(out, chunkLexemes(string(runes[i:k]))...)
			i = k
			continue
		}
		out = append(out, chunkLexemes(chunk)...)
		i = j
	}
	return out
}

func chunkLexemes(c string) []string {
	c = strings.TrimLeft(c, "._@")
	c = strings.TrimRight(c, ".-_/@")
	if c == "" || c == "-" || c == "/" {
		return nil
	}
	c = strings.ToLower(c)

	if idx := strings.IndexByte(c, '/'); idx >= 0 {
		prefix := c[:idx]
		switch {
		case prefix == "":
			return []string{c} // absolute path
		case isHostName(prefix):
			return []string{c, prefix, c[idx:]} // url, host, url path
		case isDottedNumber(prefix):
			return []string{prefix, c[idx:]} // e.g. 192.168.1.0/24
		case strings.Trim(prefix, "-_.@") == "":
			return []string{c[idx:]}
		default:
			return []string{c} // relative path
		}
	}
	if strings.IndexByte(c, '_') >= 0 {
		var out []string
		for _, p := range strings.Split(c, "_") {
			out = append(out, chunkLexemes(p)...)
		}
		return out
	}
	if at := strings.IndexByte(c, '@'); at >= 0 {
		if at > 0 && isHostName(c[at+1:]) && strings.Count(c, "@") == 1 {
			return []string{c} // e-mail address
		}
		var out []string
		for _, p := range strings.Split(c, "@") {
			out = append(out, chunkLexemes(p)...)
		}
		return out
	}
	if strings.IndexByte(c, '.') >= 0 {
		if dash := strings.IndexByte(c, '-'); dash > 0 && isDottedNumber(c[:dash]) {
			return append([]string{c[:dash]}, chunkLexemes(c[dash+1:])...) // 1.2.3-beta
		}
		return []string{c} // host, IPv4, version, file name, decimal
	}
	if strings.IndexByte(c, '-') >= 0 {
		return hyphenLexemes(c)
	}
	return []string{c}
}

func hyphenLexemes(c string) []string {
	leading := strings.HasPrefix(c, "-")
	var parts []string
	for _, p := range strings.Split(c, "-") {
		if p != "" {
			parts = append(parts, p)
		}
	}
	allWords := len(parts) >= 2
	for _, p := range parts {
		if !hasLetter(p) {
			allWords = false
			break
		}
	}
	if allWords {
		// Hyphenated compound: the whole word plus each part.
		return append([]string{strings.Join(parts, "-")}, parts...)
	}
	// Otherwise the parts stand alone, and a number right after a hyphen
	// keeps it as a sign (2024-01-01 → 2024 -01 -01; x-1 → x -1).
	var out []string
	for i, p := range parts {
		if isDigits(p) && (i > 0 || leading) {
			p = "-" + p
		}
		out = append(out, p)
	}
	return out
}

// hostLike reports whether a raw chunk is a host name or user@host.
func hostLike(chunk string) bool {
	c := strings.ToLower(strings.TrimLeft(chunk, "._@"))
	if at := strings.LastIndexByte(c, '@'); at >= 0 {
		c = c[at+1:]
	}
	return isHostName(c)
}

func isASCIIDigit(r rune) bool { return r >= '0' && r <= '9' }

// isHostName reports a dotted name with an alphabetic top-level label,
// optionally followed by :port.
func isHostName(s string) bool {
	if colon := strings.LastIndexByte(s, ':'); colon >= 0 {
		if !isDigits(s[colon+1:]) {
			return false
		}
		s = s[:colon]
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" {
			return false
		}
		for _, r := range l {
			if !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-') {
				return false
			}
		}
	}
	tld := labels[len(labels)-1]
	return len(tld) >= 2 && isAlpha(tld)
}

func isDottedNumber(s string) bool {
	if !strings.Contains(s, ".") {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if l == "" || !isDigits(l) {
			return false
		}
	}
	return true
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func isAlpha(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !unicode.IsLetter(r) {
			return false
		}
	}
	return true
}

func hasLetter(s string) bool {
	for _, r := range s {
		if unicode.IsLetter(r) {
			return true
		}
	}
	return false
}
