# Connection, diagnostics and GUI fixes — 8 September 2026

The initial connection refusal came from the local Linux VPN helper. The running
installation still used helper protocol 13 while the current application required
protocol 16. Updating the VPS or replacing the AppImage did not replace that
system component. The bundled helper was installed through the normal
administrator prompt, and the user then confirmed a successful VPN connection.

## Changes

- Connection preparation updates an outdated bundled Linux helper before checking
  connection capabilities. Installation requires a confirmed disconnected state,
  then verifies both the helper protocol and the exact installed executable.
  Cancelling or failing the installation cannot report success. Status polling
  remains a read-only operation.
- AppImage packaging retains the original system-helper bytes, matching the
  Debian package and avoiding false update prompts caused only by the packager's
  executable rewriting. Package inspection checks this identity explicitly.
- **Settings → General → Review local component** opens a working local-component
  installation dialog on Linux. It uses the helper already bundled with the app.
  Windows directs users to its installer, which owns the VPN service installation.
- Empty error messages render no alert. This removes the blank red strip from the
  Wi-Fi settings panel while retaining visible errors when an operation fails.
- SSH credential fields remain present and disabled while a saved-login lookup
  runs. A reserved status row prevents the form from collapsing during lookup.
- VPS setup presents one fingerprint confirmation, followed by a network
  inspection. **Install SirinVPN** appears after that review and stays disabled
  when the inspection finds a blocking conflict.
- VPS release source, channel and scheduling controls use the shared field and
  checkbox styles. The release-source explanation is associated with the URL
  field without becoming part of its label.
- VPS diagnostics now query `sirinvpn-server.service`, the unit installed by the
  provisioner. The previous query used the wrong service name.
- The VPS resolver self-check uses Unbound's existing loopback listener. Queries
  from the VPS to its own tunnel address arrive over loopback and are rejected by
  the intended tunnel-only DNS firewall rule. The firewall restriction is
  preserved. The client-side DNS test still checks DNS through the VPN.

## Applying the VPS diagnostic correction

The new application carries the corrected VPS executable, but rebuilding the app
does not deploy it to a running server. No VPS deployment was performed during
this fix, and the user's active VPN connection was left running.

When ready for a brief VPS service restart, open the new application and use
**Settings → VPS maintenance → Repair VPS configuration**. That existing workflow
reinstalls the bundled server software while preserving identities and access.
Review the displayed configuration before applying it. Rerun diagnostics after
reconnecting. The signed-release update screen requires a separately configured,
authenticated release source; these engineering packages are not an update feed.

## Validation

- 168 frontend tests in 36 files passed, including empty-alert handling, helper
  installation feedback, delayed SSH lookup, and the two-step setup review.
- 41 desktop and 72 server Rust library tests passed. Five opt-in server network
  tests were not run in this fix. A new test exchanges an actual TCP DNS request
  with a loopback listener while the configured tunnel address is absent.
- TypeScript/Vite, affected native Clippy checks, Windows cross-target Clippy
  checks, privacy checks, Rust formatting and whitespace checks passed.
- Synthetic Chromium checks passed at 1220×780 and 1024×680: no blank Wi-Fi alert,
  explicit component installation, styled release fields, stable SSH field
  geometry, network inspection before installation, no horizontal overflow and
  no page errors. These checks do not install a helper or contact a real VPS.
- Earlier platform acceptance remains tied to the exact older artifacts named
  in its reports. The connected user report is not a replacement for full native
  acceptance of these new packages.

## Build handoff

The refreshed packages and checksums are collected in the
[GUI-fix handoff](../target/deliverables/2026-09-08/gui-fixes/README.md).
The prior [feature builds](feature-completion-2026-09-08.md) remain available.

Windows and Android packages retain the previous engineering-build limits:
Windows uses the GNU LLVM debug target; its application-routing driver is unsigned
and remains gated by normal Windows signing policy. Android APKs use development
signing. Publisher signatures, authenticated release manifests and native
platform qualification remain separate requirements.
