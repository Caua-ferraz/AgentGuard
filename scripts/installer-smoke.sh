#!/bin/sh
# installer-smoke.sh — install AgentGuard the way a user does, then check
# what the installer left behind. Run by .github/workflows/installer-smoke.yml.
#
#   MODE=published  the public one-liner: .../releases/latest/download/install.sh | sh
#   MODE=local      this checkout's scripts/install.sh, installing WANT_VERSION
#                   (how a pull request tests installer changes before release)
#   WANT_VERSION    the release that should end up installed, e.g. 1.2.0
#
# POSIX sh, like install.sh: it runs under dash, busybox and macOS's sh.
set -eu

REPO="Caua-ferraz/AgentGuard"
URL="https://github.com/$REPO/releases/latest/download/install.sh"
MODE="${MODE:-published}"
WANT="${WANT_VERSION:?set WANT_VERSION, e.g. 1.2.0}"
WANT="${WANT#v}"
HERE="$(cd "$(dirname "$0")" && pwd)"
export AGENTGUARD_NO_UPDATE_CHECK=1

ok() { printf 'PASS  %s\n' "$*"; }
bad() { printf 'FAIL  %s\n' "$*"; exit 1; }
fetch() { # fetch <url> [<output file>]; stdout when no file is given
  if command -v curl >/dev/null 2>&1; then
    if [ $# -gt 1 ]; then curl -fsSL -o "$2" "$1"; else curl -fsSL "$1"; fi
  else
    if [ $# -gt 1 ]; then wget -q -O "$2" "$1"; else wget -qO- "$1"; fi
  fi
}
install_agentguard() { # runs the installer under test with the caller's env
  case "$MODE" in
    published) fetch "$URL" | sh ;;
    local) AGENTGUARD_VERSION="$WANT" sh "$HERE/install.sh" ;;
    *) bad "MODE must be published or local, not $MODE" ;;
  esac
}

echo "== $MODE installer, $(uname -s) $(uname -m), user $(id -un), expecting $WANT"

# 1. Fresh install.
out="$(install_agentguard 2>&1)" || { echo "$out"; bad "installer exited non-zero"; }
echo "$out" | sed 's/^/    | /'
if echo "$out" | grep -q "Checksum verified"; then ok "checksum verified"; else bad "no 'Checksum verified' line"; fi
if echo "$out" | grep -q "Installed AgentGuard $WANT"; then ok "installed $WANT"; else bad "no 'Installed AgentGuard $WANT'"; fi

if [ "$(id -u)" = "0" ]; then
  dir=/usr/local/bin conf=/etc/agentguard
else
  dir="$HOME/.local/bin" conf="${XDG_CONFIG_HOME:-$HOME/.config}/agentguard"
fi

# 2. All three binaries, runnable, at the expected version.
for t in agentguard agentguard-mcp-gateway agentguard-llm-proxy; do
  if [ -x "$dir/$t" ]; then ok "$dir/$t is executable"; else bad "missing $dir/$t"; fi
done
v="$("$dir/agentguard" --version 2>&1)"
case "$v" in *"$WANT"*) ok "agentguard --version -> $v" ;; *) bad "version was: $v" ;; esac

# 3. The starter policy exists and validates.
if [ -f "$conf/default.yaml" ]; then ok "starter policy at $conf/default.yaml"; else bad "no starter policy in $conf"; fi
if "$dir/agentguard" validate --policy "$conf/default.yaml" >/dev/null 2>&1; then ok "starter policy validates"; else bad "starter policy failed validate"; fi

# 4. Running it again reinstalls cleanly and keeps the operator's policy.
printf '# operator edit\n' >> "$conf/default.yaml"
out2="$(install_agentguard 2>&1)" || { echo "$out2"; bad "second run exited non-zero"; }
if echo "$out2" | grep -q "Installed AgentGuard $WANT"; then ok "rerun reinstalls $WANT"; else echo "$out2"; bad "unexpected rerun output"; fi
if tail -n 1 "$conf/default.yaml" | grep -q "operator edit"; then ok "rerun kept the existing policy"; else bad "rerun overwrote the policy"; fi

# 5. The PATH hint names the file a zsh user's shell reads (macOS's default
#    shell never reads ~/.profile). Only the checkout's installer is held to
#    this; a published one predating the fix still says ~/.profile.
if [ "$MODE" = local ] && [ "$(id -u)" != "0" ]; then
  hint="$(PATH=/usr/bin:/bin SHELL=/bin/zsh AGENTGUARD_VERSION="$WANT" /bin/sh "$HERE/install.sh" 2>&1)" || bad "zsh-hint run failed"
  if echo "$hint" | grep -q ">> ~/.zshrc"; then ok "PATH hint for a zsh user names ~/.zshrc"; else echo "$hint"; bad "zsh PATH hint wrong"; fi
fi

# 6. A tampered archive is refused and nothing is installed. Serving the
#    mirror from disk needs curl (busybox wget has no file:// support).
if command -v curl >/dev/null 2>&1; then
  case "$(uname -s)" in Linux) os=linux ;; Darwin) os=darwin ;; esac
  case "$(uname -m)" in x86_64 | amd64) arch=amd64 ;; aarch64 | arm64) arch=arm64 ;; esac
  archive="agentguard_${WANT}_${os}_${arch}.tar.gz"
  mirror="$(mktemp -d)" target="$(mktemp -d)"
  fetch "https://github.com/$REPO/releases/download/v$WANT/$archive" "$mirror/$archive"
  fetch "https://github.com/$REPO/releases/download/v$WANT/checksums.txt" "$mirror/checksums.txt"
  printf 'tampered' >> "$mirror/$archive"
  # Exported in a subshell: an assignment before a function call is not
  # reliably passed on to the commands inside it in every POSIX shell.
  if tout="$(export AGENTGUARD_DOWNLOAD_URL="file://$mirror" AGENTGUARD_INSTALL_DIR="$target"; install_agentguard 2>&1)"; then
    echo "$tout"; bad "installer accepted a tampered archive"
  fi
  if echo "$tout" | grep -q "checksum mismatch"; then ok "tampered archive refused (checksum mismatch)"; else echo "$tout"; bad "refused, but not for the checksum"; fi
  if [ ! -e "$target/agentguard" ]; then ok "nothing installed from the tampered archive"; else bad "a binary was installed"; fi
else
  echo "SKIP  tamper check (needs curl for a file:// mirror)"
fi

echo "ALL PASS"
