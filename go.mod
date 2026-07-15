module github.com/Caua-ferraz/AgentGuard

go 1.25.0

// Pin the build toolchain to the patched stdlib release. go1.25.12 carries
// the fix for GO-2026-5856 (crypto/tls Encrypted Client Hello privacy leak);
// go1.25.11 and earlier trip the CI govulncheck gate.
toolchain go1.25.12

require (
	github.com/fsnotify/fsnotify v1.10.1
	github.com/jackc/pgx/v5 v5.9.1
	gopkg.in/yaml.v3 v3.0.1
	modernc.org/sqlite v1.38.2
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v0.1.9 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/exp v0.0.0-20250620022241-b7579e27df2b // indirect
	golang.org/x/sync v0.17.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/text v0.29.0 // indirect
	modernc.org/libc v1.66.3 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)
