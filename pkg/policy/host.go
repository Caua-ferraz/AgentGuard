package policy

import (
	"net/netip"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// canonicalHost writes a host the one way domain rules see it, so a deny on
// "169.254.169.254" also catches the other spellings that reach that address.
// URL parsers in browsers and Node (WHATWG), curl and the C library's
// inet_aton all accept them:
//
//   - IPv4 in hex, octal, decimal or shortened form (0xa9fea9fe, 2852039166,
//     0251.0376.0251.0376, 169.254.43518) becomes a dotted quad;
//   - an IPv6 address is written in its canonical form, and one that maps an
//     IPv4 address (::ffff:169.254.169.254, ::ffff:a9fe:a9fe) becomes that
//     IPv4 address;
//   - Unicode that a WHATWG parser folds to ASCII (fullwidth digits and
//     letters, circled letters, the ideographic full stop) is folded the same
//     way (NFKC), so "１６９。２５４。１６９。２５４" is 169.254.169.254, and the
//     invisible characters it drops (soft hyphen, zero-width space, variation
//     selectors and the other default-ignorable code points) are dropped;
//   - a trailing dot ("metadata.google.internal.", the DNS root) is dropped;
//   - in a request's domain field, written by a caller or a model:
//     surrounding whitespace, a user@ prefix and a :port are dropped.
//
// host is already lower-cased. An ordinary ASCII hostname returns after one
// scan without allocating, so the hot path is unchanged.
func canonicalHost(host string) string { return canonicalize(host, true) }

// canonicalRuleHost is canonicalHost for a rule's domain. A port or userinfo
// there is kept: dropping it would widen the rule ("localhost:3000" would
// allow every port on localhost) and change its name in the audit log.
func canonicalRuleHost(host string) string { return canonicalize(host, false) }

func canonicalize(host string, request bool) string {
	if host == "" || plainHostname(host) {
		return host
	}
	host = strings.TrimSpace(host)
	if !isASCII(host) {
		host = foldUnicodeHost(host)
	}
	if request {
		if i := strings.LastIndexByte(host, '@'); i >= 0 {
			host = host[i+1:]
		}
		host = stripPort(host)
	}
	if len(host) > 1 && host[len(host)-1] == '.' {
		host = strings.TrimRight(host, ".")
	}
	if host == "" || isDottedQuad(host) {
		return host
	}
	if strings.Contains(host, ":") {
		addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
		if err != nil {
			return host
		}
		return addr.Unmap().WithZone("").String()
	}
	if host[0] <= '9' {
		if ip, ok := parseLooseIPv4(host); ok {
			return ip
		}
	}
	return host
}

// plainHostname reports whether host is an ASCII name starting with a
// letter, with no whitespace, userinfo, port or trailing dot: nothing for
// canonicalHost to do.
func plainHostname(host string) bool {
	c := host[0]
	if c < 'a' || c > 'z' {
		return false
	}
	for i := 1; i < len(host); i++ {
		switch c := host[i]; {
		case c >= 0x80, c <= ' ', c == '@', c == ':':
			return false
		}
	}
	return host[len(host)-1] != '.'
}

// foldUnicodeHost maps a non-ASCII host the way a WHATWG URL parser does
// before it reads the host: default-ignorable code points are removed, the
// rest is NFKC-folded and lower-cased, and the ideographic full stops become
// dots.
func foldUnicodeHost(host string) string {
	host = strings.Map(func(r rune) rune {
		if isIgnorable(r) {
			return -1
		}
		return r
	}, host)
	host = strings.ToLower(norm.NFKC.String(host))
	return strings.NewReplacer("\u3002", ".", "\uff61", ".", "\uff0e", ".").Replace(host)
}

// isIgnorable reports whether r is a code point to drop from a host before
// matching: format characters (soft hyphen, zero-width space, word joiner,
// BOM), variation selectors, and the other default-ignorable code points
// (combining grapheme joiner, Hangul fillers). A WHATWG parser either drops
// these too (the same host) or rejects the URL (nothing is fetched), so
// dropping them can't make a different host look like an allowed one. The
// zero-width joiner and non-joiner are the exception: the parser keeps them
// (a different, punycoded host), so they stay and the host matches nothing.
func isIgnorable(r rune) bool {
	if r == '\u200c' || r == '\u200d' {
		return false
	}
	return unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Variation_Selector, r) ||
		unicode.Is(unicode.Other_Default_Ignorable_Code_Point, r)
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// stripPort drops a numeric :port from host[:port] or [v6]:port. A bare IPv6
// address (several colons, no brackets) is left alone.
func stripPort(host string) string {
	if strings.HasPrefix(host, "[") {
		if i := strings.IndexByte(host, ']'); i > 0 {
			return host[:i+1]
		}
		return host
	}
	if strings.Count(host, ":") != 1 {
		return host
	}
	h, port, _ := strings.Cut(host, ":")
	for i := 0; i < len(port); i++ {
		if port[i] < '0' || port[i] > '9' {
			return host
		}
	}
	return h
}

// isDottedQuad reports whether host is already an IPv4 address in the one
// form canonicalHost writes (four decimal parts, no leading zeros), so it
// can be returned without re-serialising.
func isDottedQuad(host string) bool {
	parts, n, v := 0, 0, 0
	for i := 0; i <= len(host); i++ {
		if i == len(host) || host[i] == '.' {
			if n == 0 || v > 255 || (n > 1 && host[i-n] == '0') {
				return false
			}
			parts, n, v = parts+1, 0, 0
			continue
		}
		c := host[i]
		if c < '0' || c > '9' || n == 3 {
			return false
		}
		n, v = n+1, v*10+int(c-'0')
	}
	return parts == 4
}

// parseLooseIPv4 reads host the way inet_aton and the WHATWG URL parser do:
// one to four dot-separated parts, each decimal, 0x-hex or 0-led octal, the
// last part filling the bytes that remain. It reports false for anything
// else, such as a hostname that merely starts with a digit.
func parseLooseIPv4(host string) (string, bool) {
	parts := strings.Split(host, ".")
	if len(parts) > 4 {
		return "", false
	}
	nums := make([]uint64, len(parts))
	for i, p := range parts {
		base := 10
		switch {
		case len(p) > 1 && (strings.HasPrefix(p, "0x") || strings.HasPrefix(p, "0X")):
			p, base = p[2:], 16
			if p == "" {
				p = "0"
			}
		case len(p) > 1 && p[0] == '0':
			p, base = p[1:], 8
		}
		if p == "" {
			return "", false
		}
		n, err := strconv.ParseUint(p, base, 32)
		if err != nil {
			return "", false
		}
		nums[i] = n
	}
	var v uint64
	for i, n := range nums[:len(nums)-1] {
		if n > 255 {
			return "", false
		}
		v |= n << (8 * (3 - i))
	}
	last := nums[len(nums)-1]
	if last >= 1<<(8*(5-len(nums))) {
		return "", false
	}
	v |= last
	return strconv.FormatUint(v>>24, 10) + "." + strconv.FormatUint(v>>16&255, 10) + "." +
		strconv.FormatUint(v>>8&255, 10) + "." + strconv.FormatUint(v&255, 10), true
}
