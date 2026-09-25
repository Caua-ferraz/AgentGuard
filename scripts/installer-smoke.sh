#!/bin/sh
# installer-smoke.sh — install (and uninstall) AgentGuard the way a user
# does, then check what the installer left behind. Run by
# .github/workflows/installer-smoke.yml.
#
#   MODE=published  the public one-liner: .../releases/latest/download/install.sh | sh
#   MODE=local      this checkout's scripts/install.sh, installing WANT_VERSION
#                   (how a pull request tests installer changes before release)
#   WANT_VERSION    the release that should end up installed, e.g. 1.2.0
#
# POSIX sh, like install.sh: it runs under dash, busybox and macOS's sh.
#
# Variables exported inside $(...) below are meant to last for that one
# installer run only, which is what SC2030/SC2031 warn about.
# shellcheck disable=SC2030,SC2031
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
install_agentguard() { # runs the installer under test with the caller's env and options
  case "$MODE" in
    published) fetch "$URL" | sh -s -- "$@" ;;
    local) AGENTGUARD_VERSION="$WANT" sh "$HERE/install.sh" "$@" ;;
    *) bad "MODE must be published or local, not $MODE" ;;
  esac
}
installer_source() {
  case "$MODE" in published) fetch "$URL" ;; *) cat "$HERE/install.sh" ;; esac
}

# Uninstall and the updated/downgraded/reinstalled messages arrived after the
# v1.2.0 installer; they are checked only when the installer under test has
# them (this checkout's always does; a published one from v1.2.0 does not).
if installer_source | grep -q AGENTGUARD_UNINSTALL; then newer=1; else newer=""; fi

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
if [ -n "$newer" ]; then again_line="Reinstalled AgentGuard $WANT"; else again_line="Installed AgentGuard $WANT"; fi
if echo "$out2" | grep -q "$again_line"; then ok "rerun: $again_line"; else echo "$out2"; bad "expected '$again_line' on rerun"; fi
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

# 7. The installer says whether it updated, downgraded (with a warning) or
#    reinstalled, judged by the version the binary already there reports. A
#    stub that prints a chosen version stands in for an older or newer release.
if [ -n "$newer" ]; then
  stub="$(mktemp -d)"
  printf '#!/bin/sh
echo "agentguard 9.9.9"
' > "$stub/agentguard"
  chmod +x "$stub/agentguard"
  sout="$(export AGENTGUARD_INSTALL_DIR="$stub"; install_agentguard 2>&1)" || { echo "$sout"; bad "install over a 9.9.9 stub failed"; }
  if echo "$sout" | grep -q "Downgraded AgentGuard 9.9.9 -> $WANT"; then ok "over 9.9.9: Downgraded 9.9.9 -> $WANT"; else echo "$sout"; bad "no Downgraded line"; fi
  if echo "$sout" | grep -q "^Warning: $WANT is older than the 9.9.9 you had"; then ok "downgrade warns"; else echo "$sout"; bad "no downgrade warning"; fi

  printf '#!/bin/sh
echo "agentguard 0.1.0"
' > "$stub/agentguard"
  sout="$(export AGENTGUARD_INSTALL_DIR="$stub"; install_agentguard 2>&1)" || { echo "$sout"; bad "install over a 0.1.0 stub failed"; }
  if echo "$sout" | grep -q "Updated AgentGuard 0.1.0 -> $WANT"; then ok "over 0.1.0: Updated 0.1.0 -> $WANT"; else echo "$sout"; bad "no Updated line"; fi
  if echo "$sout" | grep -q "^Warning:"; then echo "$sout"; bad "an update must not warn"; fi
  rm -rf "$stub"
fi

# 8. Uninstall removes the three binaries and keeps the policy, saying where;
#    a second run finds nothing and still succeeds; the environment variable
#    works like the flag; --purge also deletes the policy folder; --purge on
#    its own is refused.
if [ -n "$newer" ]; then
  uout="$(install_agentguard --uninstall 2>&1)" || { echo "$uout"; bad "uninstall exited non-zero"; }
  echo "$uout" | sed 's/^/    | /'
  for t in agentguard agentguard-mcp-gateway agentguard-llm-proxy; do
    if [ ! -e "$dir/$t" ]; then ok "uninstall removed $t"; else bad "uninstall left $dir/$t"; fi
  done
  if [ -f "$conf/default.yaml" ] && echo "$uout" | grep -q "Kept your policy folder $conf"; then
    ok "uninstall kept the policy and said where"
  else
    bad "uninstall did not keep or name the policy folder"
  fi
  uout2="$(install_agentguard --uninstall 2>&1)" || { echo "$uout2"; bad "second uninstall exited non-zero"; }
  if echo "$uout2" | grep -q "not installed in $dir"; then ok "second uninstall: nothing to remove, exit 0"; else echo "$uout2"; bad "second uninstall output"; fi

  install_agentguard >/dev/null 2>&1 || bad "reinstall before the AGENTGUARD_UNINSTALL=1 check failed"
  eout="$(export AGENTGUARD_UNINSTALL=1; install_agentguard 2>&1)" || { echo "$eout"; bad "AGENTGUARD_UNINSTALL=1 exited non-zero"; }
  if [ ! -e "$dir/agentguard" ] && echo "$eout" | grep -q "Removed agentguard"; then ok "AGENTGUARD_UNINSTALL=1 uninstalls"; else echo "$eout"; bad "AGENTGUARD_UNINSTALL=1 did not uninstall"; fi

  install_agentguard >/dev/null 2>&1 || bad "reinstall before the --purge check failed"
  pout="$(install_agentguard --uninstall --purge 2>&1)" || { echo "$pout"; bad "--uninstall --purge exited non-zero"; }
  if [ ! -e "$dir/agentguard" ] && [ ! -e "$conf" ]; then ok "--purge removed the binaries and $conf"; else echo "$pout"; bad "--purge left files behind"; fi

  if mout="$(install_agentguard --purge 2>&1)"; then echo "$mout"; bad "--purge without --uninstall was accepted"; fi
  if echo "$mout" | grep -q "only applies together with --uninstall"; then ok "--purge on its own is refused"; else echo "$mout"; bad "--purge on its own: wrong message"; fi
fi

echo "ALL PASS"
