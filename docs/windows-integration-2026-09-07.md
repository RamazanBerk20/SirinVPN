# Windows integration

The Windows implementation uses a LocalSystem service, WireGuardNT and native
Windows networking APIs. The desktop and CLI remain ordinary user processes.
Source implementation and cross-build evidence do not establish Windows runtime
acceptance; the platform scenarios below belong to the later acceptance pass.

## Connection and privilege boundaries

- `sirinvpn-windows-service.exe` owns the adapter, routes, DNS, firewall and
  background transports. Its bounded command queue serializes changes. Status
  reads use a separate current snapshot so they do not wait for connection trials.
- Local named-pipe clients verify the SYSTEM pipe owner, the SCM LocalSystem
  own-process configuration, and the running service PID against the pipe PID.
  SCM queries use the existing read permissions; clients need no privileged
  process handle. Administrators remain trusted to configure the service.
  The service impersonates each client to obtain its SID. An existing session
  belongs to that SID; another interactive user cannot inspect or replace it.
  Remote clients and additional unprivileged pipe instances are rejected.
- Installation, replacement and removal require SCM administrator access and a
  protected executable. Program Files ancestors, file ownership, ACLs, reparse
  points and sharing modes are checked before trusted executables are used.
- WireGuardNT is loaded by absolute path beside the service and must match the
  architecture-specific hash in `packaging/windows/wireguard-nt.json`. Configuration
  is passed in memory. No plaintext WireGuard configuration or private-key command
  line is created, and WireGuard logging is disabled.
- Direct UDP, padded Noise UDP, Noise TCP and authenticated HTTPS transport use
  the shared implementations. Wrapped transport sockets bind to the physical
  underlay before connecting. The local UDP relay uses exclusive Windows socket
  binding so another process cannot share its receive port.

IPv4 and optional tunneled IPv6 addresses, IP/subnet selection, LAN policy, DNS
and MTU use IP Helper APIs. Route records are written before adding owned routes;
cleanup checks the recorded interface, prefix, next hop, metric and protocol.
Existing foreign routes are not replaced. The [8 September follow-up](feature-completion-2026-09-08.md)
adds selected-executable routing through an owned WFP bind-redirection driver.
The capability flag requires both its SCM running state and registered kernel
callout. Unsigned engineering packages cannot enable it under normal Windows
signature enforcement.

## Protection, recovery and current measurements

Kill switch, automatic reconnect and connect on startup remain independent.
Windows Filtering Platform rules express the selected route scope, DNS and IPv6
policy. Persistent and boot-time rules contain blocks and the necessary local
network exceptions. Adapter and service transport permissions are dynamic, so a
service crash does not leave an old interface identifier or transport exception
persistently permitted. The service checks the actual owned filter conditions.

Stopping the service for an update retains persistent protection and saved intent.
Explicit Disconnect records cleanup intent before removing owned routes and
filters, then removes the saved session. Pause retains intent and the selected
guard. A volatile boot nonce distinguishes a same-boot service restart from a
new Windows boot: reconnect policy governs the former; startup policy governs the
latter. The SCM service starts automatically to restore protection even when the
user's connection-on-startup option is disabled.

Administrator-requested uninstall can also remove the owned WFP guard when a
private session record is corrupt. It still verifies that record's file type,
ACL and path. It cannot reconstruct unknown route ownership from corrupt data,
so unrecoverable active-store routes may need an underlay reset or reboot.

The service observes physical route, source address and Windows network identity
changes. Connection attempts and transport passes have bounded deadlines and
backoff. A fresh driver handshake establishes connection health; an expired
handshake, failed carrier or changed underlay triggers the configured recovery
policy. Signed endpoint checkpoints can update the retained destination while
preserving the pinned server identity.

Latency, jitter, loss and MTU probes address only the configured VPN server inside
the tunnel. Samples remain in memory. Automatic transport optimization requires
the user's opt-in, current measurements, a quiet traffic interval and enforced
protection; an unsuccessful comparison restores the prior working candidate.

Desktop Wi-Fi automation uses the current Network List Manager identity and a
salted local fingerprint. It does not request SSIDs or enumerate remembered Wi-Fi
networks. Trusted networks are explicit user settings. An explicit disconnect
suppresses another automatic attempt until the network or policy changes. GUI
autostart uses the user's Run entry and respects Windows Startup Apps consent;
it is separate from the system service's boot behavior.

## Storage and updates

User credentials use user-scoped DPAPI and private ACLs. The service keeps one
machine-scoped DPAPI session under `%ProgramData%\SirinVPN\Service`, restricted
to SYSTEM and administrators. It contains current intent and ownership records,
not traffic samples, connection timestamps or browsing history.

Manual Windows updates use the shared signed release manifest and release-root
trust policy. The artifact kind is `windows_installer`; targets are
`x86_64-pc-windows-msvc` and `aarch64-pc-windows-msvc`. The GUI verifies the user's
selected HTTPS source, then elevates the installed coordinator with the exact
manifest digest. The coordinator copies and re-verifies the package in the
administrator-only `%ProgramData%\SirinVPNUpdates` directory. A separate protected
worker owns installation after the GUI exits.

The installed-release receipt advances only after the installer succeeds and the
registered LocalSystem service is running from the expected path at the expected
version. Compatibility checks cover shared client and Windows state. Explicit
compatible rollback preserves the highest accepted version. Interrupted work
retains its one authenticated package and pending operation for an explicit retry.
No automatic desktop release check or download is introduced.

## Packaging

Run `scripts/package-windows.ps1` on Windows with Rust's MSVC toolchain, the Visual
C++ tools for the selected architecture, Perl, Node and pnpm. Pass both already-built
Linux server payloads and the matching WDK-built routing driver. The Linux
payloads are uploaded only to an explicitly configured VPS.

Build the routing driver with `scripts/build-windows-routing-driver.py`, passing
the installed WDK/SDK root, its matching kit version, and Clang/LLD executables.
For example, from a Windows development shell with these tools installed:

```powershell
python ./scripts/build-windows-routing-driver.py `
  --wdk "C:/Program Files (x86)/Windows Kits/10" `
  --kit-version 10.0.28000.0 --architecture x64 `
  --clang "C:/Program Files/LLVM/bin/clang.exe" `
  --lld "C:/Program Files/LLVM/bin/lld-link.exe"
```

The output is unsigned. Complete the required publisher/kernel signing process
before packaging a driver intended to load under ordinary Windows policy.
Use `--architecture arm64` and the corresponding WDK libraries for ARM64.

```powershell
./scripts/package-windows.ps1 -Architecture x86_64 `
  -ServerX64 ./apps/desktop/src-tauri/binaries/sirinvpn-server-x86_64 `
  -ServerArm64 ./apps/desktop/src-tauri/binaries/sirinvpn-server-aarch64 `
  -RoutingDriver ./target/windows-routing-driver/sirinvpn-app-routing.sys
```

The script verifies the pinned WireGuardNT archive and DLL, builds the service
and CLI, then builds the desktop NSIS package. The installer requires NSIS 3.11
or newer and installs per machine into Program Files\SirinVPN. Its preparation
helper is embedded in the installer and extracted into Program Files before it
examines the existing installation. Version replacement stops the owned service
without ordinary uninstall cleanup; full uninstall asks the registered SYSTEM
service to remove SirinVPN's owned networking and encrypted session first.

WebView2 must already be installed. The prerequisite check runs before stopping
an existing service, and the installer does not download a runtime. Third-party
license notices accompany the payload. Production Authenticode and release-root
signing require the publisher's real credentials; this script produces unsigned
packages when those are not configured.

## Implementation checks on 2026-09-07

The x64 service, CLI and desktop executable were built from Linux with the
`x86_64-pc-windows-gnullvm` target and LLVM-MinGW 20260826. The Windows library and
test targets compile. The desktop TypeScript/Vite build and NSIS 3.11 package
build also pass. Platform-independent host checks passed: 39 desktop state tests,
2 file-access tests and 9 Windows policy tests. The focused release/Wi-Fi UI
checks passed (5 tests), along with the privacy and source-size gates.

`scripts/check-windows-package.py` extracts the installer without executing it.
It verifies every configured resource against its built source, allowing only
Tauri's documented three-byte NSIS bundle marker change in the GUI. It also
checks the x64 PE and both VPS ELF architectures, the pinned WireGuardNT DLL,
and normal/delayed PE dependencies. The 8 September update also verifies the
bundled routing driver against its built source, native subsystem and allowed
kernel imports. The GNU LLVM build includes Microsoft's
WebView2Loader DLL and its SDK license. Compiler unwind support is static.

The final x64 debug installer was refreshed after the shared diagnostics and
format/platform-gating changes. Its source path is
`target/x86_64-pc-windows-gnullvm/debug/bundle/nsis/SirinVPN_0.1.0_x64-setup.exe`.
The [delivery record](implementation-delivery-2026-09-07.md) provides its final
checksum, local handoff copy and inspection evidence. The final shared host gate
passed 451 Rust tests, including 10 Windows policy tests, and 157 UI tests;
workspace Clippy and formatting passed. These results do not establish an
MSVC/ARM64 build, production signing or Windows runtime behavior.

## Windows acceptance still to run

Use disposable Windows machines and the exact packaged artifacts. Cover fresh
install, repair, upgrade, compatible rollback, interrupted update and uninstall;
administrator versus ordinary-user permissions; pipe spoofing and cross-user
access; unsafe directory/DLL replacement; DPAPI and interrupted state writes;
all four transports and IPv4/IPv6/selected-route/LAN combinations; DNS and traffic
leaks across service crash, reboot, sleep and underlay transitions; startup policy
combinations; endpoint handoff; MTU and quality recovery; WebView2 prerequisite
failure; tray/background operation and Startup Apps consent. Inspect payload
signatures and dependencies for both x64 and ARM64. Compilation alone gives none
of these scenarios a passing runtime result.

API and packaging references: [WireGuardNT](https://git.zx2c4.com/wireguard-nt/about/),
[WFP object management](https://learn.microsoft.com/en-us/windows/win32/fwp/object-management),
[Network List Manager](https://learn.microsoft.com/en-us/windows/win32/api/netlistmgr/nn-netlistmgr-inetworklistmanager),
[Tauri Windows packaging](https://v2.tauri.app/distribute/windows-installer/).
