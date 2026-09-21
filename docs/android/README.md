# Android implementation — September 2026

This is a new port of the current desktop product. Historical Android reports
and APKs do not validate this implementation. Version 0.1 is published as source;
APKs and generated test evidence are local build outputs, not published releases.

## Fixed decisions

Android 10/API 29 minimum, compile/target API 36, direct APK distribution,
ARM64 and x86_64. Shared React UI in Tauri; a separately initialized `:vpn`
process owns the VPN and native Rust runtime. Binder is the process boundary.
The UI never owns or tears down an active tunnel. No production signing key is
created by the build. Administrative/fault-injection tests use disposable local
profiles and a local VPS. The authorized invitation was used for enrollment
and ordinary connection checks on the user's server.

- [Build and test commands](build-and-test.md)
- [Verification results and remaining coverage](progress.md)
- [Security and platform decisions](security-and-platform.md)
- [Feature families](features.md) and [all 646 scenarios](scenarios.json)

Local distribution output is `target/android-distribution/`; the generated capture
gallery is `target/android-catalog-evidence/index.html`. Neither is included in Git.
Use the build guide to produce the development APK and test evidence.

## Evidence

`scenarios.json` inventories all 646 catalog scenarios and 1,667 original image
references. The 204 catalog source hashes matched before implementation.
`python3 scripts/android-parity.py --check` validates inventory completeness.
Status `missing` means unfinished, not unsupported. `adapted` requires tested
equivalent outcomes. A fixture capture is presentation evidence only.

## Architecture contracts

The service publishes snapshots with a session generation and sequence, plus
separate tunnel, protection, management and operation state. Commands are explicit,
idempotent and generation-bound; stale actions cannot affect a new session.
Disconnect invalidates pending work and pauses automation until explicit resume.
Only current intent/configuration and unfinished transaction checkpoints persist.
No connected boolean, counters, traffic, connection or network history persists.

Keystore protects encrypted credential files in credential-encrypted app storage.
Protocol keys necessarily enter native engine memory; they are not falsely
described as non-exportable Keystore keys. Pre-unlock start waits for credentials.
No automatic cloud backup or device transfer may copy identity material.

An actual service-process death interrupts traffic. Recovery, when permitted,
is a new session. Force stop, system Stop, consent revocation and a competing VPN
are respected. A Recents swipe is a different event and must retain the session.

## Official references

- https://developer.android.com/develop/connectivity/vpn
- https://developer.android.com/develop/background-work/services/fgs/service-types
- https://developer.android.com/develop/background-work/services/fgs/handle-user-stopping
- https://developer.android.com/develop/ui/views/quicksettings-tiles
- https://developer.android.com/privacy-and-security/keystore
- https://developer.android.com/guide/practices/page-sizes
- https://v2.tauri.app/develop/plugins/develop-mobile/
- https://android.googlesource.com/platform/frameworks/base/+/android-10.0.0_r47/services/core/java/com/android/server/ConnectivityService.java
- https://android.googlesource.com/platform/frameworks/base/+/android-10.0.0_r47/core/java/android/content/pm/PackageManager.java
