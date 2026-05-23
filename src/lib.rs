//! `session-trace-receipt` — library surface for evaluating ctrace NDJSON
//! syscall traces against an intent-card's `hard_constraints` and emitting an
//! `autobuilder.session_trace_receipt.v1` receipt.
//!
//! The public surface is intentionally small: parse NDJSON into [`TraceEvent`]s,
//! evaluate them with [`evaluate`], and build a [`SessionTraceReceipt`] with
//! [`build_receipt`] (or [`skipped_receipt`] when the tracer was unavailable).

#![cfg_attr(not(test), forbid(unsafe_code))]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Schema identifier for the v1 receipt envelope.
pub const RECEIPT_SCHEMA: &str = "autobuilder.session_trace_receipt.v1";

/// Top-level receipt body, serialized to JSON by the CLI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionTraceReceipt {
    /// Schema URI. Always `RECEIPT_SCHEMA`.
    pub schema: String,
    /// Git HEAD sha the receipt is digest-bound to.
    pub head_sha: String,
    /// RFC3339 UTC timestamp when the trace was captured.
    pub captured_at: String,
    /// Information about the tracer that produced the underlying NDJSON log.
    pub tracer: TracerInfo,
    /// `{ constraint_name: { claimed, observed_*, violated } }` map.
    pub constraints_evaluated: serde_json::Map<String, serde_json::Value>,
    /// One of `"pass" | "concern" | "block" | "skipped"`.
    pub verdict: String,
    /// Populated when `verdict == "skipped"`; explains why the tracer was unusable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<String>,
    /// Free-form notes the evaluator wants attached.
    pub notes: Vec<String>,
}

/// Tracer provenance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TracerInfo {
    /// Tool name. Always `"ctrace"` for v1.
    pub tool: String,
    /// Tracer version string, when known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Root PID the trace was anchored to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_pid: Option<u32>,
    /// `sha256` hex of the raw NDJSON log; empty string when verdict is `"skipped"`.
    pub log_sha256: String,
    /// Absolute path to the raw NDJSON log on disk.
    pub log_path: String,
    /// Number of NDJSON event lines parsed.
    pub event_count: u64,
}

/// Single ctrace NDJSON event line.
///
/// Unknown fields are tolerated; only the fields the evaluator inspects are
/// pulled out as typed properties.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEvent {
    /// Monotonic millisecond timestamp.
    #[serde(default)]
    pub ts: u64,
    /// Event type discriminator: `"begin" | "execve" | "openat" | "unlinkat" | "connect"`.
    #[serde(default, rename = "type")]
    pub r#type: String,
    /// PID of the process that emitted the event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// Process `comm` (truncated to 16 bytes by the kernel).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comm: Option<String>,
    /// Target file for `execve`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// Target path for `openat` / `unlinkat`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Raw `openat` flags.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flags: Option<i32>,
}

/// Hard constraints extracted from the intent-card and applied by [`evaluate`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HardConstraints {
    /// Forbid any `connect` event in the trace.
    #[serde(default)]
    pub deny_network: bool,
    /// Forbid `execve` of binaries outside the hardcoded allowlist.
    #[serde(default)]
    pub deny_unsafe_runtime: bool,
    /// Limit the depth of subprocess fanout.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_subprocess_depth: Option<u32>,
}

/// Output of [`evaluate`]: the populated `constraints_evaluated` map plus the
/// aggregate verdict.
#[derive(Debug, Clone)]
pub struct ConstraintsEvaluation {
    /// Per-constraint observations, ready to be embedded in a receipt.
    pub map: serde_json::Map<String, serde_json::Value>,
    /// `"pass" | "block"` for the evaluation; `"skipped"` is reserved for the
    /// tracer-unavailable path.
    pub verdict: String,
}

/// Parse a raw NDJSON blob into a vector of [`TraceEvent`]s.
///
/// Blank lines and lines that fail to deserialize are skipped. (Tracer logs
/// can contain partial/torn last lines if the kernel was killed mid-write; we
/// favour best-effort over hard failure.)
#[must_use]
pub fn parse_ndjson(input: &str) -> Vec<TraceEvent> {
    let mut out = Vec::new();
    for raw_line in input.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(ev) = serde_json::from_str::<TraceEvent>(line) {
            out.push(ev);
        }
    }
    out
}

/// Evaluate `events` against `constraints`, producing the
/// `constraints_evaluated` map and an aggregate verdict.
///
/// Currently implemented constraint: `deny_network`. Any `connect` event marks
/// the constraint as violated and forces the verdict to `"block"`.
#[must_use]
pub fn evaluate(events: &[TraceEvent], constraints: &HardConstraints) -> ConstraintsEvaluation {
    let mut map = serde_json::Map::new();
    let mut violated_any = false;

    if constraints.deny_network {
        let connect_events: u64 = events
            .iter()
            .filter(|e| e.r#type == "connect")
            .count()
            .try_into()
            .unwrap_or(u64::MAX);
        let violated = connect_events > 0;
        if violated {
            violated_any = true;
        }
        let mut entry = serde_json::Map::new();
        entry.insert("claimed".into(), serde_json::Value::Bool(true));
        entry.insert(
            "connect_events".into(),
            serde_json::Value::Number(connect_events.into()),
        );
        entry.insert("violated".into(), serde_json::Value::Bool(violated));
        map.insert("deny_network".into(), serde_json::Value::Object(entry));
    }

    let verdict = if violated_any { "block" } else { "pass" }.to_string();
    ConstraintsEvaluation { map, verdict }
}

/// Build a populated [`SessionTraceReceipt`] from evaluator output.
#[must_use]
pub fn build_receipt(
    head_sha: String,
    captured_at: String,
    tracer: TracerInfo,
    eval: ConstraintsEvaluation,
    notes: Vec<String>,
) -> SessionTraceReceipt {
    SessionTraceReceipt {
        schema: RECEIPT_SCHEMA.to_string(),
        head_sha,
        captured_at,
        tracer,
        constraints_evaluated: eval.map,
        verdict: eval.verdict,
        skip_reason: None,
        notes,
    }
}

/// Build a `verdict = "skipped"` receipt for the tracer-unavailable path.
#[must_use]
pub fn skipped_receipt(head_sha: String, captured_at: String, reason: &str) -> SessionTraceReceipt {
    SessionTraceReceipt {
        schema: RECEIPT_SCHEMA.to_string(),
        head_sha,
        captured_at,
        tracer: TracerInfo {
            tool: "ctrace".to_string(),
            version: None,
            root_pid: None,
            log_sha256: String::new(),
            log_path: String::new(),
            event_count: 0,
        },
        constraints_evaluated: serde_json::Map::new(),
        verdict: "skipped".to_string(),
        skip_reason: Some(reason.to_string()),
        notes: Vec::new(),
    }
}

const HEX_TABLE: [u8; 16] = *b"0123456789abcdef";

const fn nibble_to_hex(nibble: u8) -> u8 {
    // `nibble` is masked to 0..=15 by the caller; match each value so the
    // table lookup never relies on indexing.
    match nibble & 0x0f {
        0 => HEX_TABLE[0],
        1 => HEX_TABLE[1],
        2 => HEX_TABLE[2],
        3 => HEX_TABLE[3],
        4 => HEX_TABLE[4],
        5 => HEX_TABLE[5],
        6 => HEX_TABLE[6],
        7 => HEX_TABLE[7],
        8 => HEX_TABLE[8],
        9 => HEX_TABLE[9],
        10 => HEX_TABLE[10],
        11 => HEX_TABLE[11],
        12 => HEX_TABLE[12],
        13 => HEX_TABLE[13],
        14 => HEX_TABLE[14],
        _ => HEX_TABLE[15],
    }
}

/// `sha256(bytes)` returned as a lowercase hex string.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut s = String::with_capacity(digest.len() * 2);
    for b in digest {
        s.push(char::from(nibble_to_hex(b >> 4)));
        s.push(char::from(nibble_to_hex(b & 0x0f)));
    }
    s
}
