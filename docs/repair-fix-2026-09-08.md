# VPS repair fix — 8 September 2026

The reported repair failure was caused by executing the staged server component
from `/run`, which is mounted `noexec` on this VPS. The command exited with status
126 before the configuration snapshot or service changes. The old server remained
healthy, but the application reduced the failure to a generic transaction error.

## Changes

The installer now stages verified executable bytes in a fresh private directory
under `/usr/local/lib`, alongside the server installation. It requires a root-owned
parent that is neither a symlink nor writable by group or other users. The staged
directory is private to root, the executable digest is checked before execution,
and an exit trap removes the directory. Release-state guards and identity checks
still run before installation. This works with `/run` mounted `noexec` and does not
change mount options.

Installation failures now retain a fixed, recognized step description and exit
status. The SSH reader extracts these from bounded output; arbitrary remote text
cannot become the displayed detail. Credentials and remote output are not added
to the error. The safe detail also survives release-build error redaction.

## Live repair result

The corrected provisioner successfully repaired the user's VPS using the saved,
pinned SSH login and the previously built server payload containing the diagnostic
corrections. Server and device identity were preserved. The installed x86_64 server
SHA-256 is:

```text
ad25d65ccfe179f2dee8978ab9b5c92407b16e645b02751f19997d91f0e24cbe
```

Read-only verification after repair confirmed the server, network, firewall and
Unbound services were active, the Unbound configuration was valid, and a real TCP
DNS request to the loopback resolver received a valid successful response. No
pending rollback or release transaction remained. The optional DoH service and
security-update timer remained inactive under the current configuration.

The repair is already applied. Close the old repair dialog and reconnect. To use
the corrected installer for future maintenance, quit the older application,
including its tray instance, and open the new AppImage. Repeating VPS repair is
unnecessary. Connection and diagnostic review in the new GUI remains a user check.

## Validation and packages

- 33 installer tests passed in the normal host suite. Five tests were opt-in.
- Two of those opt-in tests passed in a disposable root container with `/run`
  mounted `noexec`. The regression first confirms that executing the input there
  fails with permission denied, then runs the verified private copy successfully
  and checks its removal. The second test covers artifact replacement and release
  policy races. Three other opt-in installer tests were not run in this fix.
- Host installer/desktop Clippy and Windows cross-target test compilation and
  Clippy passed with warnings denied.
- The Linux package build reran all 168 frontend tests in 36 files and the
  TypeScript/Vite build. The UI source is unchanged from the previous handoff.
- Formatting, privacy, whitespace and source-size checks passed. All five new
  application packages passed static inspection; their hashes are recorded.

The [repair-fix handoff](../target/deliverables/2026-09-08/repair-fixes/README.md)
contains Linux AppImage and Debian packages, the Windows installer, both Android
APKs, and checksums. It includes the earlier feature and GUI changes. Both VPS
payloads and the Windows routing driver are unchanged from the previous handoff.

These remain engineering builds: the Windows installer is an unsigned GNU LLVM
debug build, its application-routing driver requires normal Microsoft signing,
and Android APKs use development signing. Full native platform acceptance was
not repeated. Earlier acceptance reports apply to the exact artifacts they name.
