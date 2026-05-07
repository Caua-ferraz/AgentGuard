#!/usr/bin/env bash
# bump-version.sh — Update the canonical version string across all files in the repo.
#
# Usage:
#   cd to the root of the repo
#   ./scripts/bump-version.sh <new-version>  (e.g. 0.5.0)
#
# Files updated (only the single canonical version declaration per file —
# historical references like migration names ("v0.4.0 → v0.4.1") and
# back-compat docstrings ("preserves v0.4.0 behavior") are intentionally
# NOT touched):
#   cmd/agentguard/main.go                     — var version = "X.Y.Z"
#   cmd/agentguard-mcp-gateway/main.go         — var version = "X.Y.Z"
#   cmd/agentguard-llm-proxy/main.go           — var version = "X.Y.Z"
#   plugins/python/pyproject.toml              — version = "X.Y.Z" under [project]
#   plugins/python/agentguard/adapters/mcp.py  — SDK_VERSION = "X.Y.Z"
#   plugins/typescript/package.json            — "version": "X.Y.Z"
#   plugins/typescript/package-lock.json       — top-level + root-package "version" (rewritten by npm install too)
#   Makefile                                   — VERSION=X.Y.Z
#   docs/SETUP.md                              — "version":"X.Y.Z" (curl example output)
#   docs/API.md                                — "version": "X.Y.Z" (/health response example)
#   docs/POLICY_REFERENCE.md                   — self-label "as of **vX.Y.Z**"
#
# Portability: uses perl -i -pe for in-place edit. perl is present on macOS
# (BSD) and Linux out of the box, unlike -i with no suffix (GNU sed only).

set -eo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: ./scripts/bump-version.sh <new-version>  (e.g. 0.5.0)" >&2
  exit 1
fi

NEW="$1"

# Validate semver format.
if ! [[ "$NEW" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Error: version must be semver (e.g. 0.5.0), got: $NEW" >&2
  exit 1
fi

# Detect the current version from the canonical source (main.go).
OLD=$(perl -ne 'if (/^\s*version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"/) { print $1; exit }' cmd/agentguard/main.go)

if [ -z "$OLD" ]; then
  echo "Error: could not detect current version from cmd/agentguard/main.go" >&2
  exit 1
fi

if [ "$OLD" = "$NEW" ]; then
  echo "Already at version $NEW — nothing to do."
  exit 0
fi

echo "Bumping $OLD -> $NEW"

# Each entry: "FILE|PERL_REGEX". The regex must:
#   - anchor on the canonical declaration so historical references are safe,
#   - capture the prefix in $1 so we only rewrite the version fragment.
REPLACEMENTS=(
  'cmd/agentguard/main.go|s/(^\s*version\s*=\s*")[0-9]+\.[0-9]+\.[0-9]+(")/${1}'"$NEW"'${2}/'
  'cmd/agentguard-mcp-gateway/main.go|s/(^\s*version\s*=\s*")[0-9]+\.[0-9]+\.[0-9]+(")/${1}'"$NEW"'${2}/'
  'cmd/agentguard-llm-proxy/main.go|s/(^\s*version\s*=\s*")[0-9]+\.[0-9]+\.[0-9]+(")/${1}'"$NEW"'${2}/'
  'plugins/python/pyproject.toml|s/(^version\s*=\s*")[0-9]+\.[0-9]+\.[0-9]+(")/${1}'"$NEW"'${2}/'
  'plugins/python/agentguard/adapters/mcp.py|s/(^SDK_VERSION\s*=\s*")[0-9]+\.[0-9]+\.[0-9]+(")/${1}'"$NEW"'${2}/'
  'plugins/typescript/package.json|s/(^\s*"version"\s*:\s*")[0-9]+\.[0-9]+\.[0-9]+(")/${1}'"$NEW"'${2}/'
  'Makefile|s/(^VERSION=)[0-9]+\.[0-9]+\.[0-9]+$/${1}'"$NEW"'/'
  'docs/SETUP.md|s/("version":")[0-9]+\.[0-9]+\.[0-9]+(")/${1}'"$NEW"'${2}/'
  'docs/API.md|s/("version":\s*")[0-9]+\.[0-9]+\.[0-9]+(")/${1}'"$NEW"'${2}/'
  'docs/POLICY_REFERENCE.md|s/(format as of \*\*v)[0-9]+\.[0-9]+\.[0-9]+(\*\*)/${1}'"$NEW"'${2}/'
)

for entry in "${REPLACEMENTS[@]}"; do
  FILE="${entry%%|*}"
  EXPR="${entry#*|}"
  if [ ! -f "$FILE" ]; then
    echo "  Warning: $FILE not found, skipping" >&2
    continue
  fi
  perl -i -pe "$EXPR" "$FILE"
  # Confirm the new version now appears in the file.
  if ! grep -Fq "$NEW" "$FILE"; then
    echo "Error: $FILE did not pick up $NEW — check the regex for this file" >&2
    exit 1
  fi
  echo "  Updated $FILE"
done

# package-lock.json has many "version" lines (one per transitive dep). Only
# rewrite occurrences whose previous line is the root package's own
# `"name": "@agentguard/sdk"` declaration. There are two such occurrences
# (the top-level field and the entry under packages.""). A state variable
# `$g` is set when the previous line names @agentguard/sdk and consumed by
# the very next "version" line so transitive-dep versions stay untouched.
PLOCK='plugins/typescript/package-lock.json'
if [ -f "$PLOCK" ]; then
  perl -i -pe '
    if ($g) { s/("version"\s*:\s*")[0-9]+\.[0-9]+\.[0-9]+(")/${1}'"$NEW"'${2}/; $g = 0; }
    if (/"name"\s*:\s*"\@agentguard\/sdk"/) { $g = 1; }
  ' "$PLOCK"
  if ! grep -Fq "\"version\": \"$NEW\"" "$PLOCK"; then
    echo "Error: $PLOCK did not pick up $NEW — check the perl block" >&2
    exit 1
  fi
  echo "  Updated $PLOCK"
fi

echo ""
echo "Done. All files updated to $NEW."
echo ""

# Verify the canonical declaration was rewritten in every targeted file.
# Historical references (e.g. "v0.4.0 → v0.4.1" migration names) are
# expected to remain — those are recorded below for the operator's eye,
# but failing only on residual *canonical* matches keeps the script
# usable for future bumps that span comments/docstrings.
echo "Historical references to $OLD preserved in tracked files:"
TRACKED=(
  cmd/agentguard/main.go
  cmd/agentguard-mcp-gateway/main.go
  cmd/agentguard-llm-proxy/main.go
  plugins/python/pyproject.toml
  plugins/python/agentguard/adapters/mcp.py
  plugins/typescript/package.json
  plugins/typescript/package-lock.json
  Makefile
  docs/SETUP.md
  docs/API.md
  docs/POLICY_REFERENCE.md
)
grep -Hn "$OLD" "${TRACKED[@]}" 2>/dev/null || echo "  (none)"

# Hard-fail if any *canonical* declaration still carries OLD: these
# regexes mirror the REPLACEMENTS anchors above. A match here means a
# regex above failed silently on a file that was found.
echo ""
echo "Verifying no canonical declaration still references $OLD..."
LEFTOVER=0
check_canonical() {
  local file="$1"
  local pattern="$2"
  if [ -f "$file" ] && grep -Pq "$pattern" "$file"; then
    echo "  FAIL: $file still has canonical declaration matching $pattern" >&2
    LEFTOVER=1
  fi
}
check_canonical 'cmd/agentguard/main.go'                    "^\s*version\s*=\s*\"$OLD\""
check_canonical 'cmd/agentguard-mcp-gateway/main.go'        "^\s*version\s*=\s*\"$OLD\""
check_canonical 'cmd/agentguard-llm-proxy/main.go'          "^\s*version\s*=\s*\"$OLD\""
check_canonical 'plugins/python/pyproject.toml'             "^version\s*=\s*\"$OLD\""
check_canonical 'plugins/python/agentguard/adapters/mcp.py' "^SDK_VERSION\s*=\s*\"$OLD\""
check_canonical 'plugins/typescript/package.json'           "^\s*\"version\"\s*:\s*\"$OLD\""
# package-lock.json: only the top-level (line 3) and the root-package entry
# under packages.""; both follow a `"name": "@agentguard/sdk"` line. Use perl
# to locate any leftover root-package-version line whose previous line names
# our package, ignoring transitive-dep version blocks.
if [ -f 'plugins/typescript/package-lock.json' ]; then
  if perl -ne '
    if ($g && /"version"\s*:\s*"'"$OLD"'"/) { print; exit 1; }
    $g = 1 if /"name"\s*:\s*"\@agentguard\/sdk"/;
    $g = 0 if !/"name"\s*:\s*"\@agentguard\/sdk"/ && /"name"\s*:/;
  ' 'plugins/typescript/package-lock.json'; then
    :  # no leftovers
  else
    echo "  FAIL: plugins/typescript/package-lock.json still has a root-package version $OLD" >&2
    LEFTOVER=1
  fi
fi
check_canonical 'Makefile'                                  "^VERSION=$OLD\$"
check_canonical 'docs/SETUP.md'                             "\"version\":\"$OLD\""
check_canonical 'docs/API.md'                               "\"version\":\s*\"$OLD\""
check_canonical 'docs/POLICY_REFERENCE.md'                  "format as of \*\*v$OLD\*\*"

if [ "$LEFTOVER" -ne 0 ]; then
  echo "Error: at least one canonical declaration still references $OLD — fix the script" >&2
  exit 1
fi
echo "OK — every canonical declaration now references $NEW."

echo ""
echo "Next steps:"
echo "  git diff"
echo "  git commit -am \"Bump version to $NEW\""
echo "  git tag v$NEW"
