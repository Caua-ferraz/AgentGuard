#!/usr/bin/env bash
# build-release.sh — Build the prebuilt release archives: all three binaries
# for every supported platform, one archive per platform, plus checksums.txt.
#
# Usage (from the repo root):
#   ./scripts/build-release.sh                      # version read from cmd/agentguard/main.go
#   ./scripts/build-release.sh --version 1.2.0 --commit abc1234 --src . --out dist
#
# Output (in --out):
#   agentguard_<version>_<os>_<arch>.tar.gz   (linux, darwin)
#   agentguard_<version>_windows_<arch>.zip
#   checksums.txt                             (sha256sum format, one line per archive)
# Each archive holds one directory named like the archive, containing the
# three binaries, LICENSE, NOTICE, README.md and configs/default.yaml.
#
# --src lets the release workflow build an older tag's sources with this
# script (backfilling assets onto an existing release). --version, when given,
# must match the source's own version string: a binary that reports one
# version but was built from another is worse than no binary.
#
# Every dependency is pure Go, so CGO stays off and all targets cross-compile
# from any host. Windows archives use `zip`, falling back to Python's zipfile
# module where `zip` is not installed (Git Bash, minimal containers).
set -euo pipefail

SRC="."
OUT="dist"
VERSION=""
COMMIT=""

while [ $# -gt 0 ]; do
  case "$1" in
    --src) SRC="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --version) VERSION="${2#v}"; shift 2 ;;
    --commit) COMMIT="$2"; shift 2 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

TOOLS=(agentguard agentguard-mcp-gateway agentguard-llm-proxy)
TARGETS=(linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64)

SRC="$(cd "$SRC" && pwd)"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

src_version="$(sed -nE 's/^[[:space:]]*version[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' "$SRC/cmd/agentguard/main.go" | head -n1)"
if [ -z "$src_version" ]; then
  echo "error: could not read the version from $SRC/cmd/agentguard/main.go" >&2
  exit 1
fi
if [ -z "$VERSION" ]; then
  VERSION="$src_version"
elif [ "$VERSION" != "$src_version" ]; then
  echo "error: --version $VERSION does not match the source version $src_version" >&2
  exit 1
fi
if [ -z "$COMMIT" ]; then
  COMMIT="$(git -C "$SRC" rev-parse --short HEAD 2>/dev/null || echo dev)"
fi

make_zip() { # make_zip <archive> <dir>, run from the staging directory
  if command -v zip >/dev/null 2>&1; then
    zip -qr "$1" "$2"
    return
  fi
  # Probe each candidate by running it: on Windows `python3` can be a Store
  # placeholder that exists on PATH but only prints an install hint.
  local py
  for py in python3 python; do
    if "$py" -c 'import zipfile' >/dev/null 2>&1; then
      "$py" -m zipfile -c "$1" "$2"
      return
    fi
  done
  echo "error: need zip or a working python to build Windows archives" >&2
  exit 1
}

sha256() { # sha256 <file...> in sha256sum output format
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi
}

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT

echo "Building AgentGuard $VERSION ($COMMIT) from $SRC into $OUT"
archives=()
for target in "${TARGETS[@]}"; do
  os="${target%/*}"
  arch="${target#*/}"
  name="agentguard_${VERSION}_${os}_${arch}"
  dir="$stage/$name"
  mkdir -p "$dir/configs"
  ext=""
  [ "$os" = "windows" ] && ext=".exe"

  for tool in "${TOOLS[@]}"; do
    (cd "$SRC" && CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
      go build -trimpath -ldflags "-s -w -X main.version=$VERSION -X main.commit=$COMMIT" \
      -o "$dir/$tool$ext" "./cmd/$tool")
  done
  cp "$SRC/LICENSE" "$SRC/NOTICE" "$SRC/README.md" "$dir/"
  cp "$SRC/configs/default.yaml" "$dir/configs/"

  if [ "$os" = "windows" ]; then
    archive="$name.zip"
    (cd "$stage" && make_zip "$OUT/$archive" "$name")
  else
    archive="$name.tar.gz"
    tar -C "$stage" -czf "$OUT/$archive" "$name"
  fi
  archives+=("$archive")
  echo "  $archive"
done

(cd "$OUT" && sha256 "${archives[@]}" > checksums.txt)
echo "  checksums.txt"
