#!/bin/sh
# install.sh — Install, update or uninstall AgentGuard (Linux and macOS).
#
#   curl -fsSL https://github.com/Caua-ferraz/AgentGuard/releases/latest/download/install.sh | sh
#   curl -fsSL https://github.com/Caua-ferraz/AgentGuard/releases/latest/download/install.sh | sh -s -- --uninstall
#
# Running it again updates to the latest release. It downloads the archive for
# this OS and CPU from GitHub Releases, verifies it against the release's
# checksums.txt, and installs agentguard, agentguard-mcp-gateway and
# agentguard-llm-proxy. Windows: use install.ps1 from the same release.
#
# Options (or the matching environment variable, set to 1):
#   --uninstall  AGENTGUARD_UNINSTALL  remove the three binaries; the policy
#                                      folder is kept
#   --purge      AGENTGUARD_PURGE      with --uninstall: delete the policy
#                                      folder too
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
warn() { printf 'Warning: %s\n' "$*" >&2; }
fail() { printf 'agentguard install: %s\n' "$*" >&2; exit 1; }
enabled() { case "${1:-}" in "" | 0 | false | no) return 1 ;; *) return 0 ;; esac; }

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

# version_lt A B: true when release A is older than B, comparing
# major.minor.patch numerically (a suffix such as -rc1 is ignored).
version_lt() {
  a="$1" b="$2"
  for _ in 1 2 3; do
    an="${a%%.*}" bn="${b%%.*}"
    an="${an%%[!0-9]*}" bn="${bn%%[!0-9]*}"
    : "${an:=0}" "${bn:=0}"
    [ "$an" -lt "$bn" ] && return 0
    [ "$an" -gt "$bn" ] && return 1
    case "$a" in *.*) a="${a#*.}" ;; *) a=0 ;; esac
    case "$b" in *.*) b="${b#*.}" ;; *) b=0 ;; esac
  done
  return 1
}

# Where the binaries and the starter policy go. Install and uninstall must
# agree on both, so they are worked out in one place.
install_dir() {
  if [ -n "${AGENTGUARD_INSTALL_DIR:-}" ]; then
    printf '%s\n' "$AGENTGUARD_INSTALL_DIR"
  elif [ "$(id -u)" = "0" ]; then
    printf '%s\n' /usr/local/bin
  else
    printf '%s\n' "$HOME/.local/bin"
  fi
}
config_dir() {
  if [ "$(id -u)" = "0" ] && [ -z "${AGENTGUARD_INSTALL_DIR:-}" ]; then
    printf '%s\n' /etc/agentguard
  else
    printf '%s\n' "${XDG_CONFIG_HOME:-$HOME/.config}/agentguard"
  fi
}

# The startup file the user's shell reads, relative to ~ (empty for fish):
# macOS defaults to zsh, which never reads ~/.profile; bash reads
# ~/.bash_profile for macOS's login shells and ~/.bashrc for Linux terminals.
shell_rc() {
  login_shell="${SHELL:-}"
  case "${login_shell##*/}" in
    zsh) printf '%s\n' .zshrc ;;
    bash) if [ "$os" = darwin ]; then printf '%s\n' .bash_profile; else printf '%s\n' .bashrc; fi ;;
    fish) printf '\n' ;;
    *) printf '%s\n' .profile ;;
  esac
}

uninstall="${AGENTGUARD_UNINSTALL:-}"
purge="${AGENTGUARD_PURGE:-}"
for arg in "$@"; do
  case "$arg" in
    --uninstall) uninstall=1 ;;
    --purge) purge=1 ;;
    *) fail "unknown option: $arg (options: --uninstall, --purge)" ;;
  esac
done
if enabled "$purge" && ! enabled "$uninstall"; then
  fail "--purge only applies together with --uninstall"
fi

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  MINGW* | MSYS* | CYGWIN*) fail "on Windows, run install.ps1 in PowerShell instead" ;;
  *) fail "unsupported OS: $(uname -s)" ;;
esac

if enabled "$uninstall"; then
  dir="$(install_dir)"
  confdir="$(config_dir)"
  found=""
  for tool in $TOOLS; do
    if [ -e "$dir/$tool" ]; then found=1; fi
  done
  if [ -z "$found" ]; then
    say "AgentGuard is not installed in $dir; nothing to remove."
    # A root install is invisible to a normal user, and the other way round.
    for other in /usr/local/bin "$HOME/.local/bin"; do
      if [ "$other" != "$dir" ] && [ -e "$other/agentguard" ]; then
        say "There is one in $other: run the uninstall as the user that installed it (with sudo for /usr/local/bin), or set AGENTGUARD_INSTALL_DIR=$other."
      fi
    done
    exit 0
  fi
  [ -w "$dir" ] || fail "cannot write to $dir; run the uninstall with sudo or set AGENTGUARD_INSTALL_DIR"
  for tool in $TOOLS; do
    rm -f "$dir/$tool" "$dir/.$tool.new"
  done
  say "Removed agentguard, agentguard-mcp-gateway and agentguard-llm-proxy from $dir"

  if enabled "$purge"; then
    # config_dir always ends in /agentguard; refuse anything else before rm -rf.
    case "$confdir" in */agentguard) ;; *) fail "refusing to delete unexpected folder $confdir" ;; esac
    if [ -d "$confdir" ]; then
      rm -rf "$confdir"
      say "Deleted the policy folder $confdir"
    fi
  elif [ -d "$confdir" ]; then
    say "Kept your policy folder $confdir (delete it yourself, or uninstall again with --purge)"
  fi
  say "Audit logs and the state database live where you ran \`agentguard serve\`; they were not touched."

  # The installer never edits startup files, but it asked the user to.
  if [ "$dir" != /usr/local/bin ]; then
    case ":$PATH:" in
      *":$dir:"*)
        rc="$(shell_rc)"
        if [ -n "$rc" ]; then
          say "If you added $dir to your PATH in ~/$rc, you can remove that line now."
        else
          say "If you added $dir with fish_add_path, remove it with: set -e fish_user_paths[(contains -i $dir \$fish_user_paths)]"
        fi
        ;;
    esac
  fi
  exit 0
fi

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

dir="$(install_dir)"
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

if [ -z "$previous" ]; then
  say "Installed AgentGuard $version in $dir"
elif [ "$previous" = "$version" ]; then
  say "Reinstalled AgentGuard $version in $dir (it was already on this version)"
elif version_lt "$version" "$previous"; then
  say "Downgraded AgentGuard $previous -> $version in $dir"
  if [ -n "${AGENTGUARD_VERSION:-}" ]; then
    warn "$version is older than the $previous you had. Unset AGENTGUARD_VERSION to install the latest release."
  else
    warn "$version is older than the $previous you had. The install command from releases/latest installs the newest release."
  fi
else
  say "Updated AgentGuard $previous -> $version in $dir"
fi

# Starter policy, so `serve` has something to load on a fresh machine. An
# existing file is the operator's policy and is never overwritten.
confdir="$(config_dir)"
policy="$confdir/default.yaml"
if [ ! -e "$policy" ] && mkdir -p "$confdir" 2>/dev/null && cp "$tmp/$name/configs/default.yaml" "$policy" 2>/dev/null; then
  say "Starter policy written to $policy"
fi

case ":$PATH:" in
  *":$dir:"*) ;;
  *)
    rc="$(shell_rc)"
    say ""
    say "$dir is not on your PATH. Add it, then open a new terminal:"
    if [ -n "$rc" ]; then
      say "  echo 'export PATH=\"$dir:\$PATH\"' >> ~/$rc"
    else
      say "  fish_add_path $dir"
    fi
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
say "To uninstall: curl -fsSL https://github.com/$REPO/releases/latest/download/install.sh | sh -s -- --uninstall"
