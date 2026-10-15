package policy

import (
	"net/netip"
	"strconv"
	"strings"

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
//     way (NFKC), so "１６９。２５４。１６９。２５４" is 169.254.169.254;
//   - a trailing dot ("metadata.google.internal.", the DNS root) is dropped;
//   - in a domain field written by a caller or a model: surrounding
//     whitespace, a user@ prefix and a :port are dropped.
//
// host is already lower-cased. An ordinary ASCII hostname returns after one
// scan without allocating, so the hot path is unchanged.
func canonicalHost(host string) string {
	if host == "" || plainHostname(host) {
		return host
	}
	host = strings.TrimSpace(host)
	if !isASCII(host) {
		host = strings.ToLower(norm.NFKC.String(host))
		host = strings.NewReplacer("\u3002", ".", "\uff61", ".", "\uff0e", ".").Replace(host)
	}
	if i := strings.LastIndexByte(host, '@'); i >= 0 {
		host = host[i+1:]
	}
	host = stripPort(host)
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
