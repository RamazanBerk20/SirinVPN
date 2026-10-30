# Per-device WireGuard preshared keys

Each device can now hold a WireGuard preshared key. The device generates it,
offers it at invitation enrollment or key rotation, and keeps it only after
the VPS confirms storing it. The design, the delivery rules and what the key
does and does not protect are in [architecture](architecture.md#wireguard-preshared-keys)
and [SECURITY.md](../SECURITY.md); the state migration is in
[the candidate policy](release-candidate.md#wireguard-preshared-key-migration).

The pinned management client now installs aws-lc-rs as its rustls provider.
Before this change it fell back to ring and negotiated plain X25519 with the
VPS, so a key delivered over it would have been recoverable from a recording by
a future quantum attacker. It now negotiates hybrid X25519MLKEM768.

## Verified on 2026-10-30

All runs used this worktree's source on a Linux workstation. No VPS, personal
VM or phone was used.

- **`./scripts/test.sh`** passed on the committed tree: 509 Rust tests
  (18 ignored kernel/VM tests), 233 frontend tests and 16 Python tests, plus
  formatting, clippy, maintainability, contract, privacy and shellcheck gates.

- **Unit tests** (in `./scripts/test.sh`): key generation and canonical
  validation; secrets stored before this change load and keep their shape;
  invitation requests carry the key and the scanned code's bootstrap identity
  carries none; pending enrollment keeps the key across retries, keeps it out
  of the plaintext journal, and moves to a key-less reference when the VPS does
  not confirm it; rotation stages a fresh key only when the VPS advertises
  support, keeps the original key on the transitional identity and rejects a
  reused key; device backups write schema 3 with a key, still import schemas
  1 and 2, and reject a key-bearing payload labelled 1 or 2; VPS authorization
  requires schema 6 for any key, rejects malformed keys, keeps keys out of the
  signed endpoint fingerprint, and installs or clears the key at rotation
  commit; the kernel diff touches only peers whose key differs; the Linux
  helper sends the key on stdin before the link is up and never in arguments;
  the Android UAPI text puts the hex key on the server peer; the release
  planner refuses both directions between this contract and a pre-key one.
- **Hybrid key exchange.** `management_tls_negotiates_the_hybrid_post_quantum_group`
  asserts the VPS-side negotiated group is `X25519MLKEM768`. With the provider
  line removed, the same test failed with `X25519`.
- **Kernel WireGuard in disposable containers** (`--network none`, host kernel
  module, `sirinvpn-policy-test` image):
  - `run-member-lifecycle.sh kernel_preshared_keys_gate_handshakes_and_keyless_peers_keep_working`:
    the VPS applied every device's key; a client with the matching key
    completed a handshake and reached the VPS; a client without the VPS's key
    and a client with a different key never completed a handshake; a
    pre-key peer kept working beside them; a later sync removed a dropped key
    and installed a new one.
  - `run-invitation-policy.sh`: a reusable invitation redemption that offered
    a key was confirmed, its key was in the kernel, the key-less redemption
    beside it was not confirmed, a retry offering a different key was refused,
    and the enrolled device reached the VPS only with its key.
  - `run-member-lifecycle.sh` (default test), `run-endpoint-handoff.sh` and
    `run-recovery-policy.sh` still pass with the added key reconciliation.
- **Android.** `cargo clippy -p sirinvpn-android-runtime --target
  x86_64-linux-android -- -D warnings` passed with NDK 30. A wireguard-go
  bridge test with the pinned Go 1.27.3 confirmed `preshared_key=` survives
  staging, commit and the controller's endpoint-only update.

## Not verified

- **Windows.** No Windows C toolchain exists on this workstation, so the
  WireGuardNT change (`WIREGUARD_PEER_HAS_PRESHARED_KEY`) was not compiled.
  The repository's `windows-build` CI job compiles it; nothing has run it.
- **Live clients.** No desktop, CLI or Android client connected to a real VPS
  with a key. The Linux helper path is covered by its recording runner and the
  VPS path by the kernel containers, whose clients are configured with `wg`
  directly. Android was not run on an emulator.
- **End-to-end enrollment and rotation** between a real client and VPS,
  including response loss, a VPS older than this change, and the key-less
  fallback reference move.
- **Installer, repair and signed VPS update flows** with key-bearing state,
  and restoring an encrypted server-state backup that contains keys.
- The hybrid group was asserted against the test TLS server built with the
  same aws-lc-rs defaults as the VPS listener, not against an installed VPS.

## Prompting devices without a key

Devices that have no key (an Owner provisioned over SSH or recovered offline,
and devices enrolled before this change) gain one only through key rotation.
Clients now prompt for that rotation instead of leaving it to the user to find.

**Decision: prompt, never rotate automatically.** An automatic one-time
rotation after connect was rejected because rotation:

- replaces both private keys, so a device backup exported earlier stops
  connecting. Rotating silently would invalidate the backup of the Owner, the
  device whose backup matters most, without telling anyone to export a new one;
- disconnects and reconnects, and under the kill switch pauses traffic. A
  background run on a startup, always-on or reconnect path would interrupt a
  session nobody asked to change;
- can end in `RecoveryRequired`, which blocks ordinary connects until the user
  resumes the rotation. An unattended run could turn a working connection into
  a blocked one with nobody watching.

The prompt reuses the existing rotation entry points unchanged, so pause,
explicit disconnect, the kill switch and recovery behave exactly as for a
manual rotation. No server endpoint was added.

- **Core.** `preshared_key_rotation_recommended(secret, configuration)` is true
  only when the stored identity has no key and the VPS advertises both
  `key_rotation_enabled` and `preshared_keys_enabled`.
- **Desktop and Android** (shared UI). A read-only
  `preshared_key_rotation_recommended` command (Tauri; Android runtime, listed
  as read-only in the controller) reads the identity without unlocking the
  keyring and asks the connected VPS. While connected with no pending
  rotation, Home shows "Add preshared key", which opens the rotation dialog
  with a description that says a preshared key is added and earlier backups
  stop connecting. The prompt clears on disconnect and after a completed
  rotation.
- **CLI.** After a successful `sirinvpn connect` (text output) and in
  `sirinvpn status`, a device without a key on a capable VPS gets the exact
  `sirinvpn server rotate-keys <server-id> --confirm-key-rotation` command.
  `status --json` carries `preshared_key_rotation_recommended`. A device that
  already has a key makes no extra request.

### Verified

- **`./scripts/test.sh`** passed on this tree: 510 Rust tests (18 ignored),
  235 frontend tests and 16 Python tests, plus every other gate.
- `only_a_keyless_device_on_a_capable_vps_is_prompted_to_rotate` (core): the
  prompt needs a key-less identity and both VPS capabilities.
- `useServerWorkspace` tests: the VPS is asked only while connected and with no
  pending rotation, a failed check shows nothing, the prompt clears on
  disconnect, and the check never opens or starts a rotation.
- **Rendered UI.** The screenshot catalog (Chromium, fictional API responses)
  showed the Home prompt after connecting and, from it, the rotation dialog
  with the preshared-key description; the dialog still waits for its
  confirmation checkbox and no rotation call was made.
- **Android.** `cargo clippy -p sirinvpn-android-runtime --target
  x86_64-linux-android -- -D warnings` passed with NDK 30.

### Not verified

- No desktop, Android or CLI client was run against a VPS to see the prompt or
  to follow it through a rotation; no emulator or disposable VM was used for
  this change.
- The Kotlin change (the new command in the controller's read-only list) was
  not built, and the Android layout of the prompt was not rendered.
- The CLI hint was not printed against a real VPS; only its decision function
  is tested.
