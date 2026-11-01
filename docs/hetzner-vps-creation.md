# One-click VPS on Hetzner Cloud

An Owner who has a Hetzner Cloud account can let SirinVPN rent the VPS for
them. The Owner pastes an API token, picks a location and a server type, sees
the monthly price and confirms it. SirinVPN creates a Debian 13 server and hands
it to the normal installer. The Owner never types an IP address or a password,
and never has to compare an SSH fingerprint: the server's SSH host key is
created on the Owner's device and placed on the server before it first boots.

Only Hetzner Cloud is supported. The provider code is one module,
`crates/installer/src/hetzner.rs`.

## Where to find it

- **Desktop (Linux, Windows):** add a server → **New Hetzner VPS**.
- **Android:** add a server → **Create a Hetzner server**.
- **CLI:**

  ```sh
  # Shows the server types, locations and the price of the default plan; creates nothing.
  sirinvpn server create-hetzner --name "My VPN"
  # Creates the server only if this is still the exact monthly price.
  sirinvpn server create-hetzner --name "My VPN" --location fsn1 --server-type cx23 \
    --accept-monthly-price 5.11
  ```

  The CLI reads the token from `HCLOUD_TOKEN` or asks for it with a hidden
  prompt. It accepts the DNS, private DNS record and transport options of
  `server add`.

The token needs **Read & Write** permission (Hetzner Cloud Console → the project
→ Security → API tokens).

## What happens

1. **Prices.** SirinVPN reads the locations, the server types and
   `/pricing` from `https://api.hetzner.cloud/v1`. A plan's price is the server
   type's gross monthly price plus the gross monthly price of its primary IPv4
   address, which Hetzner bills separately. Prices are added as exact decimals
   and rounded to cents. Deprecated types, and types Hetzner marks unavailable
   in a location, are not offered.
2. **Defaults.** Debian 13 (the `debian-13` system image for the type's
   architecture), the first location Hetzner lists, and the cheapest x86 type
   there. Arm types are offered only when the app carries an aarch64 server
   payload: the Android app does; the Linux packages and the Windows app pass
   one x86_64 payload, so they show x86 only. The aarch64 payload is built but
   has not had a native runtime test.
3. **Confirmation.** The Owner confirms the plan and its monthly price. When
   creating, SirinVPN reads the price again and stops if it differs from the
   confirmed one.
4. **Keys.** Two ed25519 keys are generated on the device: a root login key and
   the server's SSH host key. Desktop and CLI save the login key first, at
   `ssh-keys/<server name>` in the app's settings folder (`~/.config/sirinvpn/`
   on Linux), readable only by the user. It is a normal unencrypted OpenSSH key,
   so the Owner can also use it outside SirinVPN (`ssh -i <file> root@<IPv4>`).
   Android keeps it as the server's saved SSH login, encrypted with the Android
   Keystore like an imported key.
5. **Creation.** The login key is uploaded as a Hetzner SSH key named after the
   server, so Hetzner sets no root password. The server is created with that key,
   the label `managed-by=sirinvpn`, a name like `sirinvpn-0a1b2c3d`, public IPv4
   and IPv6, and cloud-init user data that:
   - installs the generated host key as `/etc/ssh/ssh_host_ed25519_key`
     (`ssh_keys`; existing host keys are deleted and no others are generated);
   - adds `HostKey /etc/ssh/ssh_host_ed25519_key` in
     `/etc/ssh/sshd_config.d/10-sirinvpn-host-key.conf`, so sshd offers only that
     key even if other host keys appear later;
   - authorizes the login key for root and turns SSH password login off.

   The Hetzner SSH key is deleted again right after the create request; the
   user data already authorizes the login key.
6. **Waiting.** SirinVPN polls the server until Hetzner reports `running` (up to
   5 minutes), then connects to port 22 until the server presents exactly the
   generated host key (up to 5 more minutes). Any other host key is never
   trusted: it keeps waiting and finally reports the mismatch.
7. **Host key replacement.** Hetzner keeps serving the user data, with the
   generated host private key, to the server itself (its metadata service at
   `169.254.169.254`) for as long as the server exists. So SirinVPN logs in over
   the pinned connection and has the server generate a new ed25519 host key
   (`ssh-keygen`, `sshd -t`, `systemctl reload ssh`). It reads the new public key
   over that same connection, waits until port 22 presents only the new key (up
   to 5 minutes) and pins that one. This happens before SirinVPN is installed,
   so no Member can exist yet; cloud-init seeds host keys only once per server,
   so a reboot keeps the new key. In addition, the VPS never forwards tunnel
   traffic to `169.254.0.0/16` or the known IPv6 metadata addresses, on every
   install.
8. **Installation.** The normal setup screen opens with the address filled in,
   the generated login selected and the new host key already pinned. The Owner can
   still choose the connection method and DNS, runs the network check and
   installs. The pin is also saved as a verified host key, so later Repair,
   Update and Uninstall need no fingerprint review.

## The token

The token is sent only to `api.hetzner.cloud`: the base URL is fixed in the
code, the client accepts only HTTPS, follows no redirects and uses no proxy.
It travels as a sensitive `Authorization` header, is wiped from memory when the
operation ends, and never appears in errors, logs or diagnostics. It is not
stored: everything after creation uses SSH, and deleting a half-made server
happens in the same session. On Android a pasted token is a protected native
value that expires after ten minutes. Once that time has passed, SirinVPN asks
for the token again before it creates, waits or deletes; the token field stays
on every screen that needs it.

## Failures and cancelling

SirinVPN never deletes a server without the Owner's confirmation.

| What happened | Result |
| --- | --- |
| Hetzner refuses a request (a 4xx answer) before or during the create request | Nothing was created. The uploaded Hetzner SSH key is removed and the local login key deleted. |
| The create request got no answer, a server error (5xx) or an unreadable answer | SirinVPN looks the server up by its name. If it exists, creation continues; otherwise the error asks the Owner to check the Hetzner Cloud Console for that name, and the local login key is kept. |
| The SSH key upload got no answer or a server error | SirinVPN looks the key up by its name and removes it if Hetzner stored it. No server is created. |
| The Owner stops waiting, or the server does not start, present the generated host key or take the replacement key in time | The screen offers **Delete this server**, **Wait again** and **Keep server**. The CLI asks `Delete the Hetzner server …? [y/N]`. |
| Installation fails | The setup screen shows the error and keeps **Delete this server** available until the server is installed. The CLI asks the same question. |
| The app closes during creation | The server stays in the Hetzner project. Look for its `sirinvpn-…` name or the `managed-by=sirinvpn` label in the Hetzner Cloud Console. On desktop and CLI the login key is already saved. |

Leaving the screen is blocked while the create request runs and while SirinVPN
waits or installs; afterwards, leaving while the server is neither installed nor
deleted asks for confirmation first. Deleting through SirinVPN also removes the local login
key.

## Verification

- Library tests against a local mock of the Hetzner endpoints: prices and
  filtering, pagination, success, an API refusal, a server error, a changed
  price, an unanswered create request, a lost SSH key upload, start and SSH
  timeouts, a wrong host key before and after the replacement, a failed
  replacement, cancelling and deleting. Key format tests cross-check the
  OpenSSH encoding with `ssh-keygen`. An installer test checks that the forward
  chain drops metadata addresses before any accept.
- `tests/vm/hetzner-cloud-init.sh` boots the Debian 13 generic cloud image with
  exactly the user data SirinVPN sends (guest network off). It logs in as root
  through the installer's own pinned SSH path with the generated key, checks
  that a different pin is rejected, replaces the host key as SirinVPN does,
  checks that the pre-seeded key is then refused and that `ssh-keyscan` sees only
  the new ed25519 key, also after a reboot, and that password login is refused.
- Vitest covers the screen: default plan and price, no creation without
  confirmation, leaving blocked while creating, the hand-off to setup with the
  replacement key pinned, cancelling, deletion only after confirmation, and an
  expired Android token being asked for again.

Not verified here: a real Hetzner account (the steps are below), the Android app
against Hetzner (compiled and unit-tested only) and Arm servers.

### End-to-end check with a real account

Use a throwaway Hetzner Cloud project. This creates a billed server for a few
minutes.

1. In the Hetzner Cloud Console, create a project and a Read & Write API token.
2. In SirinVPN, add a server → **New Hetzner VPS**, paste the token and select
   **Show prices**. Check that the locations and prices match the console's
   **Add Server** page (server price plus Primary IPv4).
3. Keep the default plan and create it. Within a few minutes the setup screen
   should open with the IPv4 address filled in and **Your server’s SSH key**
   instead of a fingerprint comparison.
4. In the Hetzner console, open the server: no root password was set, and
   **Security → SSH keys** shows no leftover `sirinvpn-…` key.
5. Select **Verify server**, **Check network**, then **Install SirinVPN**, and
   connect. Optionally run Repair: it should not ask to verify a fingerprint.
6. From a terminal: `ssh-keyscan <IPv4>` lists only one `ssh-ed25519` key whose
   `ssh-keygen -lf` fingerprint equals the one SirinVPN showed (not the one it
   printed while waiting, on the CLI); on the server,
   `curl -s http://169.254.169.254/hetzner/v1/userdata` still shows the
   pre-seeded `ed25519_public` key, which `ssh-keyscan` no longer sees;
   `ssh -i <key file> root@<IPv4>` works; `ssh -o PreferredAuthentications=password root@<IPv4>`
   is refused.
7. Test cancelling: create a second server, select **Stop waiting**, then
   **Delete this server**, and confirm. It disappears from the console.
8. Uninstall SirinVPN from the first server, then delete it in the console and
   revoke the token.
