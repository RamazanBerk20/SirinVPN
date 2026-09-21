# Linux startup and remembered VPN permission

`sirinprobe0` is the temporary WireGuard interface used for isolated transport
measurements. The NetworkManager notification about its removal did not mean the
application tunnel disconnected. The helper installer and Debian package now
install an exact-interface unmanaged-device rule, then reload NetworkManager's
configuration without restarting networking. Transport comparisons remain enabled.

The boot supervisor no longer grants a network-roaming grace period to a tunnel
that has not been created. It observes route readiness every 250 ms while offline
or backing off and wakes immediately on a route change. Handshake waiting compares
against the observation from before tunnel setup, so a quick reply during setup
cannot be missed and cause a further five-second wait. Full firewall reconciliation
keeps its normal cadence. Login Wi-Fi automation also checks every 250 ms while
waiting for its initial network, then returns to five-second observation. Existing
startup, trusted-network and manual-disconnect choices retain their meaning.

Helper protocol 18 adds `authorize-user`. First-time interactive setup asks an
administrator to authorize VPN controls for the invoking Linux account. AppImage
helper installation combines this grant with the installation approval; an already
installed Debian helper requests the grant separately on first interactive use.
Background Wi-Fi automation reports that setup is needed and does not initiate
an authorization or installation request.

The grant is a root-owned Polkit rule at
`/etc/polkit-1/rules.d/49-sirinvpn-user-<uid>.rules`. It contains the account name
and exact VPN-control action IDs. Polkit binds each action to the installed helper
and its first argument; neither command-line text nor a caller-supplied username
is used as an authorization boundary. The rule applies only to that account's
active local sessions and persists across reboots. No password is saved.

Connect/disconnect, pause/resume, session switching and endpoint maintenance use
the grant. Component installation/replacement, changing authorization and launching
other applications still require administrator permission. Updates retain grants.
Debian package purge removes generated grants; ordinary Disconnect does not.
To revoke manually, remove this account's generated rule as an administrator.
Polkit reloads the change automatically. Disconnect first if the current tunnel
should also be removed; revocation itself does not alter an existing connection.

The disposable VM regression is runnable using the command in
`tests/vm/README.md`. It exercises real NetworkManager and Polkit, account/session
boundaries, extra-argument rejection, native startup with delayed routes, a real
reboot without the desktop, and package purge. Build and test results accompany
the delivered packages. Wi-Fi association, DHCP, disk unlock and external network
latency remain outside SirinVPN's connection timing.
