//! `session-trace-receipt` — library surface for evaluating ctrace NDJSON
//! syscall traces against an intent-card's `hard_constraints` and emitting an
//! `autobuilder.session_trace_receipt.v1` receipt.
//!
//! The public surface is intentionally small: parse NDJSON into [`TraceEvent`]s,
//! evaluate them with [`evaluate`], and build a [`SessionTraceReceipt`] with
//! [`build_receipt`] (or [`skipped_receipt`] when the tracer was unavailable).

#![cfg_attr(not(test), forbid(unsafe_code))]

use std::fs::File;
use std::io::{self, BufRead, BufReader, Read};
use std::path::Path;

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

impl HardConstraints {
    /// Extract the `hard_constraints` block from an intent-card-shaped JSON
    /// value.
    ///
    /// Only fields that are explicitly present in the JSON contribute to the
    /// returned struct — missing fields default to "unclaimed" so that
    /// [`evaluate`] omits them from `constraints_evaluated`.
    ///
    /// Unknown sibling keys (e.g. `deny_unsafe`, project-specific extensions)
    /// are tolerated and ignored.
    #[must_use]
    pub fn from_intent_card(intent_card: &serde_json::Value) -> Self {
        let block = intent_card.get("hard_constraints");
        let Some(hc) = block else {
            return Self::default();
        };
        let deny_network = hc
            .get("deny_network")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let deny_unsafe_runtime = hc
            .get("deny_unsafe_runtime")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        let max_subprocess_depth = hc
            .get("max_subprocess_depth")
            .and_then(serde_json::Value::as_u64)
            .and_then(|v| u32::try_from(v).ok());
        Self {
            deny_network,
            deny_unsafe_runtime,
            max_subprocess_depth,
        }
    }
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

/// Allowlist of `execve` targets that are considered safe runtime invocations
/// regardless of the `deny_unsafe_runtime` constraint. Anything else counts
/// as an unsafe-runtime observation.
const SAFE_RUNTIME_PREFIXES: &[&str] = &[
    "/usr/bin/cargo",
    "/usr/bin/rustc",
    "/usr/bin/git",
    "/usr/bin/sh",
    "/bin/sh",
];

fn count_unsafe_execves(events: &[TraceEvent]) -> u64 {
    events
        .iter()
        .filter(|e| e.r#type == "execve")
        .filter(|e| {
            e.file
                .as_deref()
                .is_none_or(|f| !SAFE_RUNTIME_PREFIXES.iter().any(|p| f.starts_with(p)))
        })
        .count()
        .try_into()
        .unwrap_or(u64::MAX)
}

/// Evaluate `events` against `constraints`, producing the
/// `constraints_evaluated` map and an aggregate verdict.
///
/// Only constraints that are explicitly claimed in `constraints` appear in the
/// resulting map; this keeps the receipt honest about what the intent-card
/// actually asked for. Currently observed constraints:
///
/// - `deny_network`: violated when any `connect` event is present.
/// - `deny_unsafe_runtime`: violated when any `execve` targets a binary outside
///   the [`SAFE_RUNTIME_PREFIXES`] allowlist.
/// - `max_subprocess_depth`: violated when the count of `execve` events exceeds
///   the declared limit (subprocess-fanout proxy until ppid-based depth lands).
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

    if constraints.deny_unsafe_runtime {
        let unsafe_execves = count_unsafe_execves(events);
        let violated = unsafe_execves > 0;
        if violated {
            violated_any = true;
        }
        let mut entry = serde_json::Map::new();
        entry.insert("claimed".into(), serde_json::Value::Bool(true));
        entry.insert(
            "unsafe_execve_events".into(),
            serde_json::Value::Number(unsafe_execves.into()),
        );
        entry.insert("violated".into(), serde_json::Value::Bool(violated));
        map.insert(
            "deny_unsafe_runtime".into(),
            serde_json::Value::Object(entry),
        );
    }

    if let Some(limit) = constraints.max_subprocess_depth {
        let execve_count: u64 = events
            .iter()
            .filter(|e| e.r#type == "execve")
            .count()
            .try_into()
            .unwrap_or(u64::MAX);
        let observed_depth = execve_count;
        let violated = observed_depth > u64::from(limit);
        if violated {
            violated_any = true;
        }
        let mut entry = serde_json::Map::new();
        entry.insert(
            "claimed".into(),
            serde_json::Value::Number(u64::from(limit).into()),
        );
        entry.insert(
            "observed_depth".into(),
            serde_json::Value::Number(observed_depth.into()),
        );
        entry.insert("violated".into(), serde_json::Value::Bool(violated));
        map.insert(
            "max_subprocess_depth".into(),
            serde_json::Value::Object(entry),
        );
    }

    let verdict = if violated_any { "block" } else { "pass" }.to_string();
    ConstraintsEvaluation { map, verdict }
}

/// Restrict a vector of trace events to those whose `type` is in
/// `allowed_types`.
///
/// This is the library-side helper consumed by the future `--trace-filter`
/// CLI flag (`--trace-filter=connect,execve`). Splitting it out keeps the
/// behaviour testable today; the binary CLI will simply parse the comma list
/// and forward the slice into this function.
#[must_use]
pub fn filter_events(events: Vec<TraceEvent>, allowed_types: &[&str]) -> Vec<TraceEvent> {
    events
        .into_iter()
        .filter(|e| allowed_types.iter().any(|t| *t == e.r#type))
        .collect()
}

/// Build a [`TracerInfo`] from a raw NDJSON log on disk.
///
/// The returned struct has `log_sha256` set to the sha256 of the file bytes,
/// `log_path` set to the canonical string of the input path, and `event_count`
/// set to the number of non-empty lines. `tool` is fixed to `"ctrace"`;
/// `version` and `root_pid` are left unset for the caller to fill in if they
/// have that provenance.
///
/// # Errors
///
/// Returns any I/O error encountered while opening or reading the file.
pub fn tracer_info_from_log(log_path: &Path) -> io::Result<TracerInfo> {
    // Hash the file in a streaming fashion so large logs don't blow memory.
    let mut hasher = Sha256::new();
    let mut file = File::open(log_path)?;
    let mut buf = [0_u8; 8192];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(buf.get(..n).unwrap_or(&[]));
    }
    let digest = hasher.finalize();
    let mut log_sha256 = String::with_capacity(digest.len() * 2);
    for b in digest {
        log_sha256.push(char::from(nibble_to_hex(b >> 4)));
        log_sha256.push(char::from(nibble_to_hex(b & 0x0f)));
    }

    // Count non-empty lines via a separate pass so we don't need to keep the
    // full file in memory.
    let reopened = File::open(log_path)?;
    let reader = BufReader::new(reopened);
    let mut event_count: u64 = 0;
    for line in reader.lines() {
        let line = line?;
        if !line.trim().is_empty() {
            event_count = event_count.saturating_add(1);
        }
    }

    Ok(TracerInfo {
        tool: "ctrace".to_string(),
        version: None,
        root_pid: None,
        log_sha256,
        log_path: log_path.to_string_lossy().into_owned(),
        event_count,
    })
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
