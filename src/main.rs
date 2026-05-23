//! `session-trace-receipt` binary entry point.
//!
//! Iter-1 surface is intentionally minimal: tests drive the library directly,
//! so this `main` exists only so `cargo build --release` produces a working
//! binary. The full CLI lands in a later iteration.

#![cfg_attr(not(test), forbid(unsafe_code))]
#![allow(clippy::print_stdout, clippy::print_stderr)]

fn main() {
    println!(
        "session-trace-receipt {} — iter-1 surface only exposes the library; the full CLI lands in a later iteration. See tests/acceptance_ac*.rs for usage.",
        env!("CARGO_PKG_VERSION"),
    );
}
