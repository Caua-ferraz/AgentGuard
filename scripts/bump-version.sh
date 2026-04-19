#!/usr/bin/env bash
# bump-version.sh — Update the canonical version string across all files in the repo.
#
# Usage:
#   cd to the root of the repo
#   ./scripts/bump-version.sh <new-version>  (e.g. 0.4.1)
#
# Files updated (only the single canonical version declaration per file —
# historical references like migration names ("v0.4.0 → v0.4.1") and
# back-compat docstrings ("preserves v0.4.0 behavior") are intentionally
# NOT touched):
#   cmd/agentguard/main.go               — var version = "X.Y.Z"
#   plugins/python/pyproject.toml        — version = "X.Y.Z" under [project]
#   plugins/python/agentguard/adapters/mcp.py  — SDK_VERSION = "X.Y.Z"
#   plugins/typescript/package.json      — "version": "X.Y.Z"
#   Makefile                             — VERSION=X.Y.Z
#   docs/SETUP.md                        — "version":"X.Y.Z" (curl example output)
#
# Portability: uses perl -i -pe for in-place edit. perl is present on macOS
# (BSD) and Linux out of the box, unlike -i with no suffix (GNU sed only).

set -eo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: ./scripts/bump-version.sh <new-version>  (e.g. 0.4.1)" >&2
  exit 1
fi

NEW="$1"

# Validate semver format.
if ! [[ "$NEW" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Error: version must be semver (e.g. 0.4.1), got: $NEW" >&2
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
  'plugins/python/pyproject.toml|s/(^version\s*=\s*")[0-9]+\.[0-9]+\.[0-9]+(")/${1}'"$NEW"'${2}/'
  'plugins/python/agentguard/adapters/mcp.py|s/(^SDK_VERSION\s*=\s*")[0-9]+\.[0-9]+\.[0-9]+(")/${1}'"$NEW"'${2}/'
  'plugins/typescript/package.json|s/(^\s*"version"\s*:\s*")[0-9]+\.[0-9]+\.[0-9]+(")/${1}'"$NEW"'${2}/'
  'Makefile|s/(^VERSION=)[0-9]+\.[0-9]+\.[0-9]+$/${1}'"$NEW"'/'
  'docs/SETUP.md|s/("version":")[0-9]+\.[0-9]+\.[0-9]+(")/${1}'"$NEW"'${2}/'
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

echo ""
echo "Done. All files updated to $NEW."
echo ""
echo "Historical references to $OLD were preserved in:"
grep -rn "$OLD" cmd/agentguard/main.go plugins/python/pyproject.toml \
  plugins/python/agentguard/adapters/mcp.py plugins/typescript/package.json \
  Makefile docs/SETUP.md 2>/dev/null || echo "  (none)"
echo ""
echo "Next steps:"
echo "  git diff"
echo "  git commit -am \"Bump version to $NEW\""
echo "  git tag v$NEW"
