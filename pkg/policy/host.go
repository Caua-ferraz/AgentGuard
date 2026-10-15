package policy

import (
	"net/netip"
	"strconv"
	"strings"
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
//   - a trailing dot ("metadata.google.internal.", the DNS root) is dropped.
//
// host is already lower-cased. A name that starts with a letter is returned
// at once, so ordinary hostnames cost one byte comparison on the hot path.
func canonicalHost(host string) string {
	if len(host) > 1 && host[len(host)-1] == '.' {
		host = strings.TrimRight(host, ".")
	}
	if host == "" || (host[0] > '9' && host[0] != '[' && !strings.Contains(host, ":")) {
		return host
	}
	if strings.Contains(host, ":") {
		addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
		if err != nil {
			return host
		}
		return addr.Unmap().WithZone("").String()
	}
	if ip, ok := parseLooseIPv4(host); ok {
		return ip
	}
	return host
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
