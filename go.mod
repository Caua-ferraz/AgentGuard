module github.com/Caua-ferraz/AgentGuard

go 1.25.0

// Pin the build toolchain to the patched stdlib release. go1.26.5 carries the
// stdlib fixes for GO-2026-4866 (crypto/x509 auth bypass) and GO-2026-4870 /
// GO-2026-5856 (crypto/tls); building from source on go1.26.1 through go1.26.4
// inherits one or more of these unpatched and trips the CI govulncheck gate.
toolchain go1.26.5

require (
	github.com/fsnotify/fsnotify v1.10.1
	github.com/jackc/pgx/v5 v5.10.0
	gopkg.in/yaml.v3 v3.0.1
	modernc.org/sqlite v1.54.0
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/rogpeppe/go-internal v1.15.0 // indirect
	golang.org/x/sync v0.21.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	golang.org/x/text v0.39.0 // indirect
	modernc.org/libc v1.74.1 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)
