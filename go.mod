module github.com/Caua-ferraz/AgentGuard

go 1.25.0

// Pin the build toolchain to the patched stdlib release. Every AgentGuard
// vulnerability to date has come from the stdlib, not a module dependency, so
// this line is the project's single most load-bearing security control — and
// `go test ./...` will NOT tell you when it goes stale. Only govulncheck does.
//
// go1.26.7 carries the stdlib fixes for, in addition to the earlier
// GO-2026-4866 (crypto/x509 auth bypass) / GO-2026-4870 / GO-2026-5856
// (crypto/tls):
//   GO-2026-6218  net/url      quadratic complexity in resolvePath
//   GO-2026-6090  crypto/tls   unbounded post-handshake messages
//   GO-2026-6089  net/http     ReadHeaderTimeout skipped on the h2c check
//   GO-2026-6088  encoding/xml unbounded recursion during decode
//   GO-2026-5972  encoding/asn1 unbounded recursion
//   GO-2026-5026  x/net/idna   ASCII-only Punycode labels not rejected
//   GO-2026-5942  net          panic parsing an invalid SVCB/HTTPS RR
//   GO-2026-6091  html/template JS regexp context tracking
// The first six were reachable from AgentGuard's own call graph on go1.26.5;
// all eight are fixed as of go1.26.6, and 1.26.7 is the current patch.
toolchain go1.26.7

require (
	github.com/fsnotify/fsnotify v1.10.1
	github.com/jackc/pgx/v5 v5.10.0
	gopkg.in/yaml.v3 v3.0.1
	modernc.org/sqlite v1.57.0
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/rogpeppe/go-internal v1.15.0 // indirect
	golang.org/x/sync v0.21.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.39.0 // indirect
	modernc.org/libc v1.74.4 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)
