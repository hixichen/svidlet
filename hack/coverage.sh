#!/usr/bin/env bash
# Coverage report with a floor. Fails if line coverage drops below the minimum,
# so a change that adds untested code is caught rather than noticed later.
#
#   ./hack/coverage.sh          # summary, floor at 80%
#   ./hack/coverage.sh --html   # also open a browsable report
set -euo pipefail

MINIMUM="${COVERAGE_MINIMUM:-80}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

command -v cargo-llvm-cov >/dev/null || {
  echo "cargo-llvm-cov is required: cargo install cargo-llvm-cov --locked" >&2
  exit 1
}

# The live-Vault tests are excluded: they are ignored by default, and coverage
# should mean the same thing whether or not a Vault happens to be running.
cargo llvm-cov --workspace --summary-only "$@"

PERCENT="$(cargo llvm-cov --workspace --summary-only --json 2>/dev/null |
  python3 -c 'import json,sys; print(json.load(sys.stdin)["data"][0]["totals"]["lines"]["percent"])')"

printf '\nline coverage: %.2f%% (minimum %s%%)\n' "${PERCENT}" "${MINIMUM}"
python3 -c "import sys; sys.exit(0 if float('${PERCENT}') >= float('${MINIMUM}') else 1)" || {
  echo "FAIL: coverage is below the minimum" >&2
  exit 1
}
echo "OK"
