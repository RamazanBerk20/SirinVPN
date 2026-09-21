# Offline Owner recovery

The desktop app and CLI now create a self-contained, signed offline recovery key.
It contains a separate locally generated recovery identity, public VPS endpoint
and pinned server identity. It does not require an existing Owner device backup.
The VPS keeps only public authorization material. An encrypted `.sirrec` package
uses the existing Argon2id/XChaCha20-Poly1305 backup envelope and a separate password.

Owner recovery is disabled until the Owner creates a key or explicitly authorizes
selected current Admins to issue one. The recovery screen explains that possession
allows replacing every Owner device. Successful recovery creates new permanent
keys locally, revokes every previous Owner device, consumes the recovery key and
clears the Admin recovery policy. Other members retain their identities and access.
Replacing/revoking a key invalidates its saved copies. Removing an Admin's recovery
permission also invalidates an unconsumed key that Admin issued.

The recovery identity uses the same private management-only bootstrap quarantine
as enrollment, at a reserved address. It cannot send ordinary VPN, peer, DNS or
other local-service traffic. A one-minute receipt allows retries only for the same
new permanent keys. Desktop and CLI retain unfinished local enrollment state so
ordinary retries reuse those keys. Public metadata and separately secured private
keys are kept apart. No recovery history is recorded.

Use **Add server → Recover access** to review the key's VPS identity and confirm
replacing lost Owner devices. Replacing an existing local profile requires its own
explicit checkbox. Recovery package import decrypts and validates locally. In the
CLI, `sirinvpn server recovery --help` lists status, policy, create, revoke and
recover operations. Exports create private files without overwriting an existing
file. Recovery still needs a reachable VPS or a valid separately supplied endpoint
update; the project has no central recovery service.

Focused verification:

- Core checks cover signed server/Owner/issuer binding, modified signatures,
  encrypted package authentication, wrong passwords, and staged-key retry locking.
- The isolated kernel test creates and revokes an Admin-issued key, creates an
  Owner key, checks actual IPv4/IPv6 bootstrap restrictions, preserves the key in
  a server backup, rejects wrong callers/unconfirmed recovery, replaces multiple
  Owner peers, rejects reuse with different permanent keys, and expires the receipt.
  Run `sh tests/network/run-recovery-policy.sh`.
- The generated startup script restores the original bootstrap Owner peer only
  before authorization state exists. Saved authorization is authoritative on boot.
- UI checks require Owner-device revocation and local replacement consent and
  ignore a late preview after the key changes.

Authorization with recovery state requires schema 4; old servers fail closed.
Full acceptance on final packaged artifacts remains a separate step. No existing
VPS, live VPN connection or actual member was used by these checks.
