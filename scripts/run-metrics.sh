#!/usr/bin/env bash
# run-metrics.sh — single-script orchestrator that produces target/autobuilder/metrics.json.
#
# READ-ONLY: the edit-agent must not modify this file. Modifying the harness
# would invalidate the unfakeable-metric contract.
#
# Output: target/autobuilder/metrics.json, shape:
#   {
#     "schema": "autobuilder.metrics.v1",
#     "head_sha": "<sha>",
#     "iteration": <int or null>,
#     "scalars": { "<metric_name>": <number>, ... },
#     "ac_passing_count": <int>,
#     "ac_total_count": <int>,
#     "ac_results": [ {"id": "AC1", "level": "MUST", "passing": true|false}, ... ],
#     "audit": { "blocking_count": <int>, "advisory_count": <int> },
#     "clippy_warning_count": <int>,
#     "test_coverage_pct": <number or null>,
#     "doc_coverage_pct": <number or null>,
#     "proptest_density": <number or null>,
#     "captured_at": "<ISO 8601>"
#   }
#
# The unfakeable scalar's name comes from agent/intent-card.json's
# unfakeable_metric.name. If your project's metric requires custom collection,
# extend the SCALARS block below; do not weaken the gate steps above it.

# `errexit` is intentionally OFF — gate steps below (cargo check / clippy /
# test) can legitimately fail mid-loop, and the iteration receipt must STILL
# get a valid metrics.json so the advance/revert decision sees the failure
# as a metric regression rather than as a missing-file crash.
set -uo pipefail
cd "$(dirname "$0")/.."

OUT=target/autobuilder/metrics.json
LOG=target/autobuilder/run.log
mkdir -p target/autobuilder
: > "$LOG"

HEAD_SHA=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
CAPTURED=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# --- Hard gates ---
echo "::gate cargo check" | tee -a "$LOG"
cargo check --workspace 2>&1 | tee -a "$LOG" || true

echo "::gate cargo clippy" | tee -a "$LOG"
CLIPPY_WARNINGS=0
if ! cargo clippy --workspace --message-format=json -- -D warnings > target/autobuilder/clippy.json 2>&1; then
  CLIPPY_WARNINGS=$(jq -s '[.[] | select(.reason == "compiler-message" and .message.level == "warning")] | length' target/autobuilder/clippy.json 2>/dev/null || echo 0)
fi

echo "::gate cargo test" | tee -a "$LOG"
cargo test --workspace --no-fail-fast 2>&1 | tee target/autobuilder/test-output.txt | tee -a "$LOG" || true

# Count AC results by re-running tests with the acceptance_ prefix and parsing.
AC_TOTAL=$(find tests -maxdepth 1 -name 'acceptance_*.rs' -type f 2>/dev/null | wc -l)
AC_PASSING=0
AC_RESULTS='[]'
if [ "$AC_TOTAL" -gt 0 ]; then
  # cargo test prints "test acceptance_ac1 ... ok" lines.
  AC_PASSING=$(grep -cE '^test acceptance_[a-z0-9_]+ \.\.\. ok' target/autobuilder/test-output.txt || true)
fi

# --- Audit (BAD_RUST) ---
echo "::gate audit" | tee -a "$LOG"
AUDIT_OUT=target/autobuilder/audit.json
BLOCKING=0
ADVISORY=0
if [ -x "$HOME/.claude/skills/autobuilder/rules/audit-checks.sh" ]; then
  if ! "$HOME/.claude/skills/autobuilder/rules/audit-checks.sh" . > "$AUDIT_OUT" 2>&1; then
    : # Non-zero exit is fine; we'll read counts from the JSON.
  fi
  BLOCKING=$(jq -r '.blocking_count // 0' "$AUDIT_OUT" 2>/dev/null || echo 0)
  ADVISORY=$(jq -r '.advisory_count // 0' "$AUDIT_OUT" 2>/dev/null || echo 0)
fi

# --- Scalars ---
# Default unfakeable scalar: acceptance_tests_passing_count (a sensible CLI/lib default).
# Replace this block when the intake selects a different metric (e.g. binary_size_bytes,
# cold_start_ms, p99_latency_ms).
SCALARS_JSON=$(jq -n \
  --argjson ac "$AC_PASSING" \
  --argjson total "$AC_TOTAL" \
  '{
    acceptance_tests_passing_count: $ac,
    acceptance_tests_total_count: $total
  }')

# --- Emit ---
jq -n \
  --arg head "$HEAD_SHA" \
  --arg captured "$CAPTURED" \
  --argjson scalars "$SCALARS_JSON" \
  --argjson ac_pass "$AC_PASSING" \
  --argjson ac_total "$AC_TOTAL" \
  --argjson clippy "$CLIPPY_WARNINGS" \
  --argjson blocking "$BLOCKING" \
  --argjson advisory "$ADVISORY" \
  '{
    schema: "autobuilder.metrics.v1",
    head_sha: $head,
    iteration: null,
    scalars: $scalars,
    ac_passing_count: $ac_pass,
    ac_total_count: $ac_total,
    ac_results: [],
    audit: { blocking_count: $blocking, advisory_count: $advisory },
    clippy_warning_count: $clippy,
    test_coverage_pct: null,
    doc_coverage_pct: null,
    proptest_density: null,
    captured_at: $captured
  }' > "$OUT"

echo "metrics written to $OUT"
