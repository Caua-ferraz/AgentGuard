#!/usr/bin/env bash
# test-all.sh — Run every test suite in the repo and report a summary.
#
# Usage:
#   ./scripts/test-all.sh                       # run all suites
#   ./scripts/test-all.sh --skip-ts             # skip the TypeScript suite
#   ./scripts/test-all.sh --skip-python         # skip the Python suite
#   ./scripts/test-all.sh --no-race             # drop -race from go test (faster)
#   ./scripts/test-all.sh -h | --help
#
# Suites:
#   go       — go test -race -coverprofile=coverage.out ./...
#   policy   — agentguard validate on every YAML in configs/ and configs/examples/
#   python   — pip install -e ".[dev]" + pytest -v --cov=agentguard in plugins/python
#   ts       — npm install + npm run build + npm test in plugins/typescript
#
# Behavior:
#   - The script DOES NOT stop on first failure. Every suite runs so you
#     get a full picture; only the final summary fails the run.
#   - Suites whose toolchain is missing (no python, no npm) are reported
#     as SKIP rather than FAIL — running this on a partial toolchain is
#     a valid use case (e.g. Go-only contributors).
#   - Coverage artefacts: ./coverage.out (Go), plugins/python/.coverage,
#     plugins/typescript/coverage/ if the suites produce them.
#
# Portability: bash 3.2+. Works under Git Bash on Windows, macOS, and
# Linux. The agentguard binary used by the policy suite is detected with
# a .exe suffix when $OS=Windows_NT so the script does not assume the
# Linux binary name.

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# ---- flag parsing -----------------------------------------------------

SKIP_GO=0
SKIP_POLICY=0
SKIP_PYTHON=0
SKIP_TS=0
NO_RACE=0

show_help() {
  sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
}

while [ $# -gt 0 ]; do
  case "$1" in
    --skip-go)     SKIP_GO=1 ;;
    --skip-policy) SKIP_POLICY=1 ;;
    --skip-python) SKIP_PYTHON=1 ;;
    --skip-ts)     SKIP_TS=1 ;;
    --no-race)     NO_RACE=1 ;;
    -h|--help)     show_help; exit 0 ;;
    *)
      echo "Unknown flag: $1" >&2
      echo "Run with --help to see usage." >&2
      exit 2
      ;;
  esac
  shift
done

# ---- output helpers ---------------------------------------------------

if [ -t 1 ]; then
  C_HDR=$'\033[1;34m'   # bold blue
  C_OK=$'\033[1;32m'    # bold green
  C_FAIL=$'\033[1;31m'  # bold red
  C_SKIP=$'\033[2m'     # dim
  C_RST=$'\033[0m'
else
  C_HDR=""; C_OK=""; C_FAIL=""; C_SKIP=""; C_RST=""
fi

# Parallel arrays — bash 3.2 lacks associative arrays portably.
SUITES=()
RESULTS=()
DURATIONS=()

# Where to find the agentguard binary on this OS.
AGENTGUARD_BIN="./agentguard"
if [ "${OS:-}" = "Windows_NT" ]; then
  AGENTGUARD_BIN="./agentguard.exe"
fi

# run_suite NAME SKIP_FLAG SUITE_FN
#   Records a SUITE -> PASS/FAIL/SKIP entry and continues even on failure.
run_suite() {
  local name="$1"
  local skip_flag="$2"
  local fn="$3"

  if [ "$skip_flag" -eq 1 ]; then
    SUITES+=("$name"); RESULTS+=("SKIP"); DURATIONS+=("-")
    printf "${C_SKIP}── skipping suite: %s${C_RST}\n\n" "$name"
    return
  fi

  printf "${C_HDR}══ %s ══${C_RST}\n" "$name"
  local start end dur rc=0
  start=$(date +%s)
  # Run the suite in a subshell so a `set -e`/`exit` inside cannot abort
  # the script; capture rc explicitly.
  ( "$fn" ) || rc=$?
  end=$(date +%s)
  dur=$((end - start))

  SUITES+=("$name"); DURATIONS+=("${dur}s")
  if [ "$rc" -eq 0 ]; then
    RESULTS+=("PASS")
    printf "${C_OK}── %s passed (%ss)${C_RST}\n\n" "$name" "$dur"
  elif [ "$rc" -eq 77 ]; then
    # Sentinel rc 77 = "toolchain missing, skip cleanly".
    RESULTS+=("SKIP")
    DURATIONS[${#DURATIONS[@]}-1]="-"
    printf "${C_SKIP}── %s skipped (toolchain missing)${C_RST}\n\n" "$name"
  else
    RESULTS+=("FAIL")
    printf "${C_FAIL}── %s FAILED (rc=%d, %ss)${C_RST}\n\n" "$name" "$rc" "$dur"
  fi
}

# ---- suite runners ----------------------------------------------------

ensure_agentguard_built() {
  if [ ! -x "$AGENTGUARD_BIN" ]; then
    go build -o "$AGENTGUARD_BIN" ./cmd/agentguard
  fi
}

go_suite() {
  set -e
  if [ "$NO_RACE" -eq 1 ]; then
    go test -coverprofile=coverage.out ./...
  else
    go test -race -coverprofile=coverage.out ./...
  fi
}

policy_suite() {
  set -e
  ensure_agentguard_built
  local f any=0
  for f in configs/*.yaml configs/examples/*.yaml; do
    [ -f "$f" ] || continue
    any=1
    echo "  validate $f"
    "$AGENTGUARD_BIN" validate --policy "$f"
  done
  if [ "$any" -eq 0 ]; then
    echo "  no policy files found under configs/ — nothing to validate" >&2
  fi
}

python_suite() {
  if ! command -v python3 >/dev/null 2>&1 && ! command -v python >/dev/null 2>&1; then
    echo "python not installed" >&2
    return 77
  fi
  set -e
  # The E2E test spawns the real binary, so build it first.
  ensure_agentguard_built
  local PY=python3
  command -v python3 >/dev/null 2>&1 || PY=python
  ( cd plugins/python && \
    "$PY" -m pip install --quiet -e ".[dev]" && \
    "$PY" -m pytest -v --cov=agentguard )
}

ts_suite() {
  if ! command -v npm >/dev/null 2>&1; then
    echo "npm not installed" >&2
    return 77
  fi
  set -e
  ( cd plugins/typescript && \
    npm install --silent --no-fund --no-audit && \
    npm run build && \
    npm test )
}

# ---- run them ---------------------------------------------------------

run_suite go     "$SKIP_GO"     go_suite
run_suite policy "$SKIP_POLICY" policy_suite
run_suite python "$SKIP_PYTHON" python_suite
run_suite ts     "$SKIP_TS"     ts_suite

# ---- summary ----------------------------------------------------------

printf "${C_HDR}══ summary ══${C_RST}\n"
fail=0
i=0
for name in "${SUITES[@]}"; do
  r="${RESULTS[$i]}"
  d="${DURATIONS[$i]}"
  case "$r" in
    PASS) printf "  ${C_OK}%-5s${C_RST}  %-8s  %s\n" "$r" "$name" "$d" ;;
    FAIL) printf "  ${C_FAIL}%-5s${C_RST}  %-8s  %s\n" "$r" "$name" "$d"; fail=1 ;;
    SKIP) printf "  ${C_SKIP}%-5s  %-8s  %s${C_RST}\n" "$r" "$name" "$d" ;;
  esac
  i=$((i + 1))
done

exit "$fail"
