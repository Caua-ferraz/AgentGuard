#!/bin/sh
# install.sh — Install or update AgentGuard (Linux and macOS).
#
#   curl -fsSL https://github.com/Caua-ferraz/AgentGuard/releases/latest/download/install.sh | sh
#
# Running it again updates to the latest release. It downloads the archive for
# this OS and CPU from GitHub Releases, verifies it against the release's
# checksums.txt, and installs agentguard, agentguard-mcp-gateway and
# agentguard-llm-proxy. Windows: use install.ps1 from the same release.
#
# Environment variables:
#   AGENTGUARD_VERSION       version to install, e.g. 1.2.0 (default: this
#                            script's release, or the latest release)
#   AGENTGUARD_INSTALL_DIR   where the binaries go (default: /usr/local/bin
#                            when run as root, otherwise ~/.local/bin)
#   AGENTGUARD_DOWNLOAD_URL  base URL holding the release assets, for mirrors
#                            and air-gapped installs (default: GitHub Releases)
#
# POSIX sh on purpose: it runs under dash, busybox and macOS's sh.
set -eu

REPO="Caua-ferraz/AgentGuard"
TOOLS="agentguard agentguard-mcp-gateway agentguard-llm-proxy"
# The release workflow replaces this placeholder with the release's version,
# so a script downloaded from a given release installs that release. Run from
# a source checkout, the placeholder survives and the latest release is used.
RELEASE_VERSION="@AGENTGUARD_VERSION@"

say() { printf '%s\n' "$*"; }
fail() { printf 'agentguard install: %s\n' "$*" >&2; exit 1; }

fetch() { # fetch <url> <output file>
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 3 -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$2" "$1"
  else
    fail "need curl or wget"
  fi
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | cut -d' ' -f1
  else
    fail "need sha256sum or shasum to verify the download"
  fi
}

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  MINGW* | MSYS* | CYGWIN*) fail "on Windows, run install.ps1 in PowerShell instead" ;;
  *) fail "unsupported OS: $(uname -s)" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  aarch64 | arm64) arch=arm64 ;;
  *) fail "unsupported CPU: $(uname -m)" ;;
esac

version="${AGENTGUARD_VERSION:-}"
if [ -z "$version" ]; then
  case "$RELEASE_VERSION" in
    *@*) ;;
    *) version="$RELEASE_VERSION" ;;
  esac
fi
tmp="$(mktemp -d 2>/dev/null || mktemp -d -t agentguard)"
trap 'rm -rf "$tmp"' EXIT INT TERM
if [ -z "$version" ]; then
  fetch "https://api.github.com/repos/$REPO/releases/latest" "$tmp/latest.json" ||
    fail "could not look up the latest release; set AGENTGUARD_VERSION"
  version="$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$tmp/latest.json" | head -n 1)"
  [ -n "$version" ] || fail "could not read the latest release tag; set AGENTGUARD_VERSION"
fi
version="${version#v}"

base="${AGENTGUARD_DOWNLOAD_URL:-https://github.com/$REPO/releases/download/v$version}"
name="agentguard_${version}_${os}_${arch}"
archive="$name.tar.gz"

say "Downloading AgentGuard $version for $os/$arch"
fetch "$base/$archive" "$tmp/$archive" || fail "download failed: $base/$archive"
fetch "$base/checksums.txt" "$tmp/checksums.txt" || fail "download failed: $base/checksums.txt"

# checksums.txt is sha256sum output; a "*" before the name marks binary mode.
expected="$(awk -v f="$archive" '{ n = $2; sub(/^\*/, "", n); if (n == f) print $1 }' "$tmp/checksums.txt")"
[ -n "$expected" ] || fail "$archive is not listed in checksums.txt"
actual="$(sha256_of "$tmp/$archive")"
[ "$expected" = "$actual" ] || fail "checksum mismatch for $archive (expected $expected, got $actual)"
say "Checksum verified"

tar -xzf "$tmp/$archive" -C "$tmp"

if [ -n "${AGENTGUARD_INSTALL_DIR:-}" ]; then
  dir="$AGENTGUARD_INSTALL_DIR"
elif [ "$(id -u)" = "0" ]; then
  dir="/usr/local/bin"
else
  dir="$HOME/.local/bin"
fi
mkdir -p "$dir" || fail "cannot create $dir"
[ -w "$dir" ] || fail "cannot write to $dir; set AGENTGUARD_INSTALL_DIR or run with sudo"

previous=""
if [ -x "$dir/agentguard" ]; then
  # The update check would add a network call and a stderr notice here.
  previous="$(AGENTGUARD_NO_UPDATE_CHECK=1 "$dir/agentguard" --version 2>/dev/null | awk '{print $2}' || true)"
fi

for tool in $TOOLS; do
  # Copy then rename: replacing the file by rename is safe even while an
  # older copy of the binary is running.
  cp "$tmp/$name/$tool" "$dir/.$tool.new"
  chmod 0755 "$dir/.$tool.new"
  mv -f "$dir/.$tool.new" "$dir/$tool"
done

if [ -n "$previous" ] && [ "$previous" != "$version" ]; then
  say "Updated AgentGuard $previous -> $version in $dir"
else
  say "Installed AgentGuard $version in $dir"
fi

# Starter policy, so `serve` has something to load on a fresh machine. An
# existing file is the operator's policy and is never overwritten.
if [ "$(id -u)" = "0" ] && [ -z "${AGENTGUARD_INSTALL_DIR:-}" ]; then
  confdir="/etc/agentguard"
else
  confdir="${XDG_CONFIG_HOME:-$HOME/.config}/agentguard"
fi
policy="$confdir/default.yaml"
if [ ! -e "$policy" ] && mkdir -p "$confdir" 2>/dev/null && cp "$tmp/$name/configs/default.yaml" "$policy" 2>/dev/null; then
  say "Starter policy written to $policy"
fi

case ":$PATH:" in
  *":$dir:"*) ;;
  *)
    say ""
    say "$dir is not on your PATH. Add it, for example:"
    say "  echo 'export PATH=\"$dir:\$PATH\"' >> ~/.profile && . ~/.profile"
    ;;
esac

say ""
if [ -e "$policy" ]; then
  say "Next: agentguard serve --policy $policy --dashboard"
else
  say "Next: agentguard serve --policy <policy.yaml> --dashboard"
fi
say "Docs: https://github.com/$REPO#quickstart"
say "To update later, run the same install command again."
