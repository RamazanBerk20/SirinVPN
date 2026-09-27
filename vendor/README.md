# GLib 0.18 backport

Tauri's GTK3 stack requires GLib 0.18. The registry's 0.18.5 release contains
the `VariantStrIter` output-pointer defect in RUSTSEC-2024-0429. This directory
preserves the checksum-verified upstream crate and its MIT license, with the
two-line upstream fix backported and an isolated regression-test lockfile.
`glib-upstream.json` records the archive, upstream commit and complete tree hash.

`python3 scripts/check-vendored.py` verifies the reviewed source tree and Cargo's
path selection. The shared gate and dependency scan run this check. The upstream
regression is `cargo test --manifest-path vendor/glib/Cargo.toml --locked --release
--lib variant_iter::tests`; use a target directory outside `vendor/glib` so build
output cannot enter the reviewed tree. On the recorded Linux/Rust 1.97.1 run,
the pristine optimized test crashed with SIGSEGV and the patched run passed all
11 iterator tests. See `docs/remediation.md` for evidence and limits.

The package retains version 0.18.5. Raw advisory reports may therefore still list
it; no advisory is suppressed. This backport mitigates the named pointer defect,
not unrelated future findings. Remove the patch when the supported GTK/Tauri
dependency chain carries the upstream fix. Treat vendor updates as source review,
including license, provenance, tree hash and the negative binding regression.
