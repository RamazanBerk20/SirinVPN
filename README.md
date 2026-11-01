<p align="center">
  <img src="apps/desktop/src/assets/sirin-mark.png" alt="SirinVPN logo" width="96" />
</p>

# SirinVPN

**Your VPS. Your VPN.**

SirinVPN is a self-hosted WireGuard VPN with Linux, Windows, and Android clients.
Set up a server you control, connect your devices, and share access through signed
invitations. Server setup, connections, device administration, and recovery live
in the same app.

There is no SirinVPN account or hosted control service. The clients communicate
directly with your VPS, with no built-in analytics or traffic-history database.

**Version 0.1** · `0.1.1` in package manifests · [AGPL-3.0-only](LICENSE)

This is an early development version, published as source code. There are no
published binary releases or AUR packages yet.

[Getting started](#getting-started) · [Build from source](#build-from-source) ·
[Platform status](#platform-status) · [Documentation](#documentation)

## A look at the app

<img src="docs/images/desktop.png" alt="SirinVPN desktop Home: connect button, connection method and kill switch status, this device's traffic, and server stats" width="960" />

<details>
<summary>Android interface</summary>
<p>
  <img src="docs/images/android.png" alt="SirinVPN Android Home: connect button, server picker, live traffic, connection settings, and bottom navigation" width="320" />
</p>
</details>

Screenshots use fictional profiles and example data.

## What it does

- **Set up your own server.** Provision a Debian 13 or Ubuntu 24.04 LTS VPS over SSH, verify its host
  fingerprint, review its network before installation, and manage SirinVPN-owned
  services and firewall rules.
- **Choose a connection method.** Direct UDP (standard WireGuard), Obfuscated UDP,
  TLS fallback with a pinned certificate, and TCP fallback. Pick one yourself or let
  SirinVPN choose for your network conditions, with configurable endpoints and
  bounded automatic fallback.
- **Manage people and devices.** Owner, Admin, and Member roles; signed invitations
  and QR enrollment; device revocation, access limits, and delegated permissions.
- **Control routing and DNS.** Full-tunnel or selected-subnet routing, explicit LAN
  access, platform-specific application routing, recursive, DoT, or DoH DNS
  with private records and split zones, and opt-in
  [ad and tracker blocking](docs/dns-blocking.md) for every device.
- **Keep the VPN independent of the interface.** Native services own the tunnel.
  Android includes notification controls, a Quick Settings tile, a home-screen
  widget, permission-protected [automation intents](docs/android/automation.md)
  for apps such as Tasker, Android TV support, and integration with Android's
  Always-on VPN and lockdown settings.
- **See current measurements.** Download and upload rates, connection time, server
  resource use, private-tunnel quality, and MTU measurements without an activity
  timeline or stored traffic history.
- **Recover and maintain access.** Encrypted device and VPS backups, recovery
  keys, key rotation, server repair, and signed endpoint migration.

Availability and verification vary by platform. The
[desktop feature map](docs/overhaul-feature-map.md) and
[Android feature matrix](docs/android/features.md) describe the individual paths.

## Platform status

| Platform | Implementation / build path | Verification and limits |
| --- | --- | --- |
| **Linux** | Desktop, CLI, privileged helper, systemd and nftables; Debian/AppImage packaging. | Disposable kernel and exact Debian package acceptance passed. Two earlier fallback DNS observations remain unresolved; AppImage runtime and wider desktops need qualification. |
| **Android 10+** | Separate VPN process, Keystore, QR, notifications, Quick Settings, a home-screen widget, automation intents and Android TV (leanback, D-pad); ARM64/x86_64 APK build paths. | Debug APK, API 29/36 instrumentation and Samsung S25+ lifecycle/lockdown checks passed. Other OEMs, overnight power behavior and physical 16 KB pages remain unqualified. Android TV is checked in Chromium and by package metadata, not on a TV. |
| **Windows** | LocalSystem service, WireGuardNT, WFP and DPAPI; MSVC/NSIS tooling. | Native Windows 11 units, cross-user controls, four transports and crash/reboot checks passed; exact scope is in the remediation ledger. Broader release qualification remains open. Executable routing requires a signed, qualified driver. |
| **VPS** | Debian 13 and Ubuntu 24.04 LTS x86_64/ARM64 server payloads with private management, DNS and relays. | Cross-architecture builds do not establish ARM64 native runtime acceptance. Ubuntu 24.04 x86_64 passed the disposable-VM install/repair/rollback gate and the two-VM client lab (four transports, DNS, kill switch, uninstall); IPv6 and ARM64 on Ubuntu are not yet verified ([record](docs/ubuntu-24-04-vps-2026-10-29.md)). |

macOS and iOS clients are not implemented. Android parity, device-specific power
behavior, and several recovery/update workflows still need broader verification;
see the [Android verification report](docs/android/progress.md). Historical test
reports apply to their named builds, not every subsequent change.

The [26 September remediation report](docs/remediation.md) records exact current
results, local evidence paths, configured CI, and release blockers. New Linux
credentials require the system keyring. Permission-protected, unencrypted file
fallback requires explicit consent in Settings → General → Credential storage
or `sirinvpn storage allow-private-file`; existing legacy profiles remain readable.
On Linux, clicking Connect can request a system keyring unlock after login or wake;
background status checks and Wi-Fi automation never display an unlock prompt.

## Getting started

You need a VPS you administer, running Debian 13 or Ubuntu 24.04 LTS, with privileged SSH access and
reachable ports for the connection methods you choose. SirinVPN does not provide
servers or a VPN subscription.

1. **Build the client** for your platform using the instructions below.
2. **Set up your VPS.** On the first screen choose **My VPS** (**Set up my VPS** on
   Android), enter the server address and an SSH login, and select **Verify server**.
   Compare the fingerprint with your hosting provider's web console or another
   trusted channel before you select **Fingerprint matches**. After the network
   check, select **Install SirinVPN**.
3. **Connect** from Home, accepting the operating system's VPN or administrator
   prompt when needed. Run desktop clients as your ordinary user; the native
   service handles privileged networking.
4. **Add other devices.** On a device that is already set up, open **Devices** and
   select **Invite member**, or **Add device** in a member's menu. On the new
   device, choose **Invitation** (**Use an invitation** on Android) and scan the QR
   code or enter the code. For an iPhone, iPad, Mac or router with the official
   WireGuard app, select **Add WireGuard device** instead and scan its QR code in
   that app ([details](docs/wireguard-devices.md)).

### Finding your way around

| Page | What it holds |
| --- | --- |
| **Home** | Connect and disconnect, the active server, and this device's traffic and connection time. The desktop layout also shows live server stats; on Android, **Connection** opens the method, kill switch, and reconnect options, and **Connection details** shows status, addresses, and server stats. |
| **Servers** | Your saved servers: search, switch, rename, mark favorites, add a server, and open maintenance. |
| **Devices** | Members and devices on the selected server: invitations, roles, access policies, port forwarding, and revocation. |
| **Settings** | **General** (Wi-Fi auto-connect on desktop, startup, notifications, app updates, credential storage), **Connection** (method, kill switch, reconnect), **Network** (app routing, DNS, ports), **Keys & recovery** (keys, backups, recovery keys), and **VPS maintenance** (health, diagnostics, updates; **Diagnostics** on Android). |

On Android, notification permission enables app notifications. The Android app has
no Wi-Fi auto-connect and does not request location permission.

## Build from source

```sh
git clone https://github.com/RamazanBerk20/SirinVPN.git
cd SirinVPN
```

The repository pins Rust in [`rust-toolchain.toml`](rust-toolchain.toml) and pnpm
in [`apps/desktop/package.json`](apps/desktop/package.json). The current development
toolchain uses Rust 1.97.1, Node.js 26, and pnpm 11.3.0.

### Linux

For Debian and AppImage artifacts, the container build supplies the native build
dependencies and builds the bundled server and helper:

```sh
./scripts/package-linux-container.sh
```

This requires Docker. Outputs are under `target/release/bundle/deb/` and
`target/release/bundle/appimage/`. Building locally does not publish a release.

For development, install the Linux native dependencies listed in
[Development](docs/development.md), then run:

```sh
pnpm --dir apps/desktop install --frozen-lockfile
CARGO_BUILD_JOBS=4 cargo build --workspace --locked
pnpm --dir apps/desktop tauri dev
```

VPN operations also need the native helper and system integration; a frontend
development server alone does not install them.

### Android

Android builds require JDK 17, Android SDK 36, NDK `30.0.16248370`, Go 1.27.3,
the Android Rust targets, and both bundled VPS server payloads. Follow the
[Android build guide](docs/android/build-and-test.md) to prepare those inputs.
With them in place:

```sh
pnpm --dir apps/desktop install --frozen-lockfile
export GO_BIN="$(command -v go)"
sh scripts/build-android.sh all debug
```

The APK is written to
`apps/desktop/src-tauri/gen/android/app/build/outputs/apk/universal/debug/app-universal-debug.apk`.
This is a development build. Generated Android files live under
`apps/desktop/src-tauri/gen/`; edit the tracked sources in
`apps/desktop/android/` instead.

### Windows

Use [`scripts/package-windows.ps1`](scripts/package-windows.ps1) on Windows with
the MSVC toolchain, Visual C++ tools, Perl, Node.js, pnpm, the two Linux VPS
payloads, and a matching routing driver. Required arguments and platform limits
are documented in [Windows integration](docs/windows-integration-2026-09-07.md).
Cross-compilation alone does not establish Windows runtime support.

## Development and tests

Fast frontend checks:

```sh
pnpm --dir apps/desktop test
pnpm --dir apps/desktop build
```

The full local gate includes source-size checks, Python tests, Rust formatting,
Clippy, workspace tests, frontend checks, and privacy invariants:

```sh
./scripts/test.sh
```

Some native tests require isolated VMs or emulators and are intentionally not run
by a normal workspace test. See [Testing](docs/testing.md) and the
[Android test guide](docs/android/build-and-test.md). Administrative and destructive
acceptance tests belong on disposable infrastructure, never a personal VPS.

## How it is organized

| Path | Responsibility |
| --- | --- |
| `apps/desktop/src/` | Shared React interface with desktop and Android layouts |
| `apps/desktop/src-tauri/` | Tauri host and native command adapters |
| `apps/desktop/android/` | Android services, permissions, notifications, QR scanning, and WireGuard bridge |
| `crates/core/`, `crates/protocol/` | Profiles, identities, invitations, management, and shared contracts |
| `crates/server/`, `crates/installer/` | VPS services and SSH provisioning/maintenance |
| `crates/transport/` | Direct and authenticated fallback carriers |
| `crates/linux-helper/`, `crates/windows-service/`, `crates/android-runtime/` | Platform-owned VPN lifecycles |
| `tests/`, `scripts/`, `packaging/` | Validation, build tooling, and system integration |

## Privacy and security

Each device generates its own permanent identity. SSH setup verifies the server's
host key; management traffic uses a private tunnel endpoint with certificate
pinning and mutual TLS. Credentials stay in native storage, with platform-specific
protection. See [Security](SECURITY.md) and [Privacy](PRIVACY.md) for the boundaries.

A VPN does not remove trust in your device, VPS operator, hosting provider, or
chosen DNS resolver. Alternative transports cannot guarantee connectivity when
the server address or required ports are blocked. No independent security audit
is claimed for version 0.1.

For ordinary bugs, [open an issue](https://github.com/RamazanBerk20/SirinVPN/issues)
with your platform, build, and reproduction steps. Do not attach real invitation
codes, keys, passwords, backups, or private VPS details.

## Documentation

- [Development](docs/development.md) and [architecture](docs/architecture.md)
- [Testing](docs/testing.md) and [source map](docs/module-map.md)
- [Android build, design, and verification](docs/android/README.md)
- [Desktop feature map](docs/overhaul-feature-map.md)
- [Interface text and localization](docs/ui-text.md) — writing guide and how to add a language
- [Windows integration](docs/windows-integration-2026-09-07.md)
- [Signed update design](docs/releases.md) — implementation documentation; no published releases yet

## License

SirinVPN is licensed under the **GNU Affero General Public License v3.0 only**.
See [LICENSE](LICENSE). Third-party components retain their own licenses;
platform-specific notices are included with the corresponding build tooling.
