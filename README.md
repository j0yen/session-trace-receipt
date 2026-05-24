# session-trace-receipt

> Prove runtime-level compliance with hard_constraints that are invisible to source review.

## Why

Prove runtime-level compliance with hard_constraints that are invisible to source review. The existing 7-receipt gate validates what the build SAYS (clippy, deny, grep); it cannot prove what the runtime DOES (subprocess transitivity, build.rs behavior, silent abort sites). A syscall-level session trace turns 'no network' or 'no out-of-target writes' from a static-grep guess into an unfakeable receipt, in the autoresearch sense.

## Build

```sh
cargo build --release
```

Produces `target/release/session-trace-receipt`. Symlink into `~/.local/bin/` if you want it on `$PATH`.

## Usage

```sh
session-trace-receipt --help
```

## Audience

The autobuilder loop itself, and every PRD whose intent-card declares a deny_* hard_constraint (deny_network, deny_unsafe_runtime, max_subprocess_depth, future deny_filesystem_writes_outside_target). Runs on the the author laptop and any Linux CI runner with bpftrace + sudoers access for the tracer.

## Acceptance criteria

This project was scaffolded from a PRD via the `autobuilder` pipeline. The MUST-level acceptance criteria are:

- **AC1**: `autobuilder loop --trace` shells out to `ctrace start --root <pid>` before the metric-harness spawn and `ctrace stop` after, capturing NDJSON to target/autobuilder/session-trace.ndjson.
- **AC2**: When ctrace is unavailable (missing binary, sudo denied, bpftrace missing), `--trace` emits a session-trace.json receipt with verdict=skipped and a skip_reason field; does NOT abort the iteration.
- **AC3**: The receipt validates against autobuilder.session_trace_receipt.v1 schema and is digest-bound (sha256 envelope matching other receipts).
- **AC4**: constraints_evaluated block is populated from intent_card.hard_constraints — only declared constraints appear, each with claimed, an observed counterpart, and a violated bool.
- **AC5**: When deny_network:true is claimed and the trace contains >=1 connect event, verdict=block.
- **AC6**: `autobuilder gate` walks 8 receipts (was 7); existing 7 receipts continue to pass on the autobuilder repo without modification.

Each AC has a matching integration test under `tests/acceptance_ac<n>.rs`.

## Provenance

Built via the [`autobuilder`](https://github.com/j0yen/autobuilder) pipeline (PRD intake -> intent-card -> scaffold -> iterate-and-prove). Originally consolidated as a subdir of the [`wintermute`](https://github.com/j0yen/wintermute) monorepo; this standalone repo is a fresh-init snapshot for easier consumption and distribution.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
