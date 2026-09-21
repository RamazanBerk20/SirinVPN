# Member policies and reusable invitations

Owners and Admins can set ordinary-member device limits, expiration, weekly UTC
access windows and explicit permissions to invite members, add their own devices,
manage peer access or manage their own port forwards. Only the Owner can restrict
an Admin. Owner access stays unrestricted. Timed policies govern private API
authorization immediately and synchronize WireGuard peers, wrapper authorization
and forwarding rules on the server's one-second policy tick. No activity history
is stored. Reducing a device limit requires revoking excess devices first.

Invitations support 1–100 joins and signed member policy. Each redemption creates
new permanent keys on the joining device and receives independent membership,
device and address allocations. Additional-device invitations retain the existing
member and enforce its current device limit. Owner device invitations remain
single use. Delegated member invitations cannot amplify the issuer's permissions,
device limits, expiration or schedule. Remaining uses are current authorization
state, not a record of who joined or when. Short enrollment receipts support a
lost response without consuming another use.

The application exposes these controls in Devices and the invitation dialog. The
CLI accepts `server invite --max-uses N --policy-file policy.json` and
`server set-member-policy SERVER MEMBER --policy-file policy.json`. Members see
only their own membership and issued invitations. Policies and new grants require
authorization schema 3; older daemons reject that state. The encrypted backup and
installer preflight recognize this version. Reusable Android enrollment bindings
use profile registry/journal version 4 so old clients cannot misread allocations.

Temporary bootstrap peers are restricted to private IPv4 mTLS enrollment. They
cannot reach DNS or other local services or forward IPv4/IPv6 packets. Static
installer rules and atomic runtime chains enforce the restriction before adding
new peers. The chain behavior follows the
[nftables manual](https://netfilter.org/projects/nftables/manpage.html).

Focused verification on 6 September:

- Core invitation checks cover signed scope, fresh allocations and authority tampering.
- Protocol and server checks cover UTC boundaries, scope amplification, limits,
  expiration, private persistence, recovery of access and manager boundaries.
- `tests/network/run-invitation-policy.sh` passed with real WireGuard, nftables,
  IPv4/IPv6 input and forwarding in a disposable container with no external network.
  Concurrent redemption, retries, exhaustion and additional-device limits passed.
- The frontend suite passed 109 tests; TypeScript compilation passed.

This is implementation verification. It does not replace the full release
acceptance run, and no live VPS was updated by these checks.
