# Dependency finding review — 27 September 2026

The first hosted [dependency run](https://github.com/RamazanBerk20/SirinVPN/actions/runs/36333718092)
on `8cea53c` scanned 959 package records and returned nine advisory records with
no license violations. Two records describe the same patched GLib defect. The
other records are six Rust maintenance notices and the unused Go OpenPGP package.
That scanner exit was correctly preserved, but the gate had no distinction
between reviewed findings and new blockers.

`scripts/check-dependencies.py` now retains the complete raw OSV JSON and its
exit code, and produces a separate Markdown disposition summary. The gate allows
only the exact advisory IDs, ecosystems and versions below, **until 27 December
2026**. Every other advisory or license violation blocks. New aliases are not
automatically accepted. Scanner errors, absent/incomplete reports, inconsistent
exit codes, missing lockfiles and unavailable verification tools also fail.

| Exact finding | Package and version | Disposition and scope |
|---|---|---|
| [RUSTSEC-2024-0429](https://rustsec.org/advisories/RUSTSEC-2024-0429.html), [GHSA-wrw7-89jp-8q8g](https://github.com/advisories/GHSA-wrw7-89jp-8q8g) | crates.io `glib` 0.18.5 | Fixed by the reviewed upstream backport in the Linux GTK dependency. Each scan first verifies the entire vendored tree, manifest and Cargo lock selection with `check-vendored.py`. A changed tree or registry fallback fails before any exception applies. |
| [RUSTSEC-2024-0370](https://rustsec.org/advisories/RUSTSEC-2024-0370.html) | crates.io `proc-macro-error` 1.0.4 | Build-time GTK/GLib procedural-macro dependency. Temporarily accept this maintenance notice; it does not identify a specific exploit or offer a patched version. |
| [RUSTSEC-2025-0081](https://rustsec.org/advisories/RUSTSEC-2025-0081.html) | crates.io `unic-char-property` 0.9.0 | Maintenance notice inherited through `urlpattern` and Tauri utilities. |
| [RUSTSEC-2025-0075](https://rustsec.org/advisories/RUSTSEC-2025-0075.html) | crates.io `unic-char-range` 0.9.0 | Same Unicode dependency chain and maintenance scope. |
| [RUSTSEC-2025-0080](https://rustsec.org/advisories/RUSTSEC-2025-0080.html) | crates.io `unic-common` 0.9.0 | Same Unicode dependency chain and maintenance scope. |
| [RUSTSEC-2025-0100](https://rustsec.org/advisories/RUSTSEC-2025-0100.html) | crates.io `unic-ucd-ident` 0.9.0 | Same Unicode dependency chain and maintenance scope. |
| [RUSTSEC-2025-0098](https://rustsec.org/advisories/RUSTSEC-2025-0098.html) | crates.io `unic-ucd-version` 0.9.0 | Same Unicode dependency chain and maintenance scope. |
| [RUSTSEC-2026-0370](https://rustsec.org/advisories/RUSTSEC-2026-0370.html) | crates.io `zvariant` 5.15.0 | Maintenance notice: merged into `zbus` 6. Inherited through `zbus` 5, which `notify-rust` 4.18 and `tauri-plugin-single-instance` 2.4 require. |
| [RUSTSEC-2026-0371](https://rustsec.org/advisories/RUSTSEC-2026-0371.html) | crates.io `zbus_names` 4.3.4 | Same `zbus` 5 dependency chain and maintenance scope. |
| [RUSTSEC-2026-0372](https://rustsec.org/advisories/RUSTSEC-2026-0372.html) | crates.io `zvariant_derive` 5.15.0 | Same `zbus` 5 dependency chain and maintenance scope. |
| [GHSA-qwgh-2vcv-g2f7](https://github.com/advisories/GHSA-qwgh-2vcv-g2f7) | crates.io `block-buffer` 0.10.4 | The advisory needs a cursor stored in the buffer's last byte, which a panicking `compress` callback can overwrite. Version 0.10.4 stores the cursor in a separate `pos` field that the callback cannot reach. The only fixed release, 0.12.1, needs the `digest` 0.11 stack, which `sha2`, `argon2` and `ed25519-dalek` do not use yet. |
| [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932) | Go `golang.org/x/crypto` 0.58.0 | The affected OpenPGP packages are absent from the Android bridge's production import graph. Every scan uses the pinned Go toolchain to run `go list -mod=readonly -deps ./...` for Android arm64 and amd64 with CGO enabled. Importing OpenPGP or any subpackage, or failing to obtain either graph, blocks the scan. |

On 9 October 2026, the Go disposition was rechecked for `x/crypto` 0.57.0,
required by the `x/net` 0.60.0 security update. Both Android import graphs still
exclude OpenPGP. The exact advisory ID, verification and expiry stay unchanged;
the former 0.56.0 disposition no longer applies. On 29 October 2026, the `x/net`
0.62.0 security update moved it to `x/crypto` 0.58.0; both graphs still exclude
OpenPGP.

The Unicode packages occur in build and runtime dependencies; their notices are
not dismissed as unreachable. Their temporary acceptance preserves the compatible
Tauri stack while upstream dependency replacement is reviewed. The Rust
maintenance notices must still be classified as `unmaintained` without a severity score;
reclassified advisories block. Locked dependency versions, scheduled scans and
blocking new advisories limit this exception; they do not eliminate maintenance
risk. Replace these packages through compatible GTK/Tauri updates when available,
then remove their dispositions. Review again before the expiry date rather than
automatically extending it.

On 29 October 2026, three `zbus` 5 component crates received the same kind of
maintenance notice. They carry desktop notifications and single-instance D-Bus
calls on Linux. No stable `notify-rust` or Tauri single-instance release depends
on `zbus` 6 yet, so the same exact-version, no-severity and expiry rules apply.
Remove these dispositions when those dependents move to `zbus` 6. Remove the
`block-buffer` disposition when the RustCrypto `digest` 0.11 stack is adopted, or
earlier if a 0.10 release is reported as affected.

Remove the GLib disposition when the supported dependency stack includes the
upstream fix. Reassess the Go disposition whenever the dependency version changes;
never use the unmaintained OpenPGP package. No package-wide advisory ignore or
scanner `IgnoredVulns` entry is introduced. Existing version-bound license
metadata in `osv-scanner.toml` remains separate.

Locally, use the Go version in the bridge's `go.mod` on `PATH`, or set `GO_BIN` to
that executable. Use a fresh `--output` filename for every scan. The dependency
workflow installs that pinned Go version and publishes both raw findings and
their review summary, including on failure. A green result means this scoped
policy passed; it does not mean the scanner returned no notices or that release
qualification is complete.
