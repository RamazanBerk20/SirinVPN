# Scheduled VPS backups

The Owner can have the app save an encrypted VPS backup on a schedule and keep
the newest ones in a folder they choose. It is the same backup as **Back up
VPS**: the same pinned SSH export, the same password-based envelope and the same
**Restore or migrate VPS** path. Backups never leave the Owner's device or the
folder they pick; SirinVPN uploads them nowhere.

## Setting it up

- **Desktop and Android:** **Settings → Keys & recovery → VPS backup and
  recovery → Scheduled backups**. Choose a folder, how often (daily, weekly or
  every 30 days), how many backups to keep (1–30) and a backup password of at
  least 12 characters.
- The schedule uses the VPS's **saved SSH login** and its pinned host key. Run
  **Back up VPS** once with **Remember login** on first; the dialog says so when
  no login is saved.
- **Back up now** runs the schedule immediately and shows the result.
- **Turn off** deletes the schedule and the saved backup password. Removing the
  server from the app does the same. A server removed with the CLI keeps both
  until the app next starts, which then deletes them.

## When a backup runs

A backup is due when the interval has passed since the last successful VPS
backup from this device; a manual **Back up VPS** (app or CLI) also counts. The
app checks every 15 minutes while it is running (the desktop app keeps running
in the tray; the Android app while it is open) and runs a due backup only while
this device is **disconnected** from the VPN, with no kill switch or
auto-reconnect waiting. This is the rule every VPS backup already follows: the
export uses a direct SSH session, which the tunnel and kill switch are not set
up to carry. The first check waits a minute after disconnecting, so opening the
app to connect does not start a backup first. A failed attempt is retried after
an hour.

Each run:

1. checks the device is disconnected (otherwise it waits, and records nothing);
2. reads the saved SSH login and backup password from secure storage, without a
   prompt (only **Back up now** may ask to unlock it);
3. exports the encrypted backup to
   `sirinvpn-vps-<server id>-<UTC time>.sirinvpn-server-backup` in the folder;
4. deletes this server's oldest scheduled backups beyond the limit. Only regular
   files with exactly that name pattern for this server are touched; other
   files, links and folders stay.

## Status and warnings

The app keeps one current status per server: when the schedule was turned on,
the last successful backup and the last failure with its reason. A success
clears the failure. There is no run history.

- **Settings** shows the age of the last backup on the **Scheduled backups**
  row and in the dialog.
- **Home** shows a plain note with a **Review** button when the last attempt
  failed, or when no backup succeeded within one interval plus a day
  (**overdue**).
- **CLI:** `sirinvpn server backup-status` (and `--json`) prints the same
  status. It cannot run or change the schedule: the CLI has no saved SSH logins
  or backup password. CLI backups made with `server backup-vps` reset the clock.

## Where things are stored

| Item | Desktop | Android |
| --- | --- | --- |
| Schedule and status | `vps-backup-schedules.json` in the client configuration directory, mode 0600 | Same file in no-backup app storage |
| Backup password | OS credential store (Secret Service, Windows Credential Manager), service `org.sirinvpn.client.vps-backup` | Keystore-encrypted vault |
| SSH login | The existing saved login (OS credential store) | The existing saved login (vault) |
| Backups | The chosen folder | The chosen document folder (persisted Storage Access Framework permission) |

No plaintext password is written to disk. Linux's opt-in private-file
credential fallback does not apply: the backup password needs the Secret
Service.

## Tests

- `crates/core/src/vps_backup_schedule/tests.rs`: UTC file names, rotation keeps
  exactly the newest N of one server and ignores other servers' files, unrelated
  files, folders and links; due, retry and stale rules; a scheduled backup that
  went through rotation decrypts with the restore reader and matches its
  snapshot.
- `apps/desktop/src/features/settings/VpsBackupScheduleDialog.test.tsx`: the
  runner waits for a disconnected device and a minute's grace, runs only due
  schedules and shows the recorded failure; the dialog saves a confirmed
  password and keeps it when editing; missing SSH login and turning off.

## Limits

- Scheduled backups need the app running and the device disconnected. A device
  that is always connected gets the overdue note instead of backups.
- Android has no background job: backups run while the app is open.
- The folder can be a synced folder (for example one a cloud client mirrors);
  that is the Owner's choice and is outside SirinVPN.
