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

The application exposes these controls in Devices, under **Limits and permissions** for a person and in the **Add device** flow (the join-code dialog). Current UI names: **Device limit**, **Access ends**, **Weekly hours**, and the permissions **Add new people**, **Add their own devices**, **Change device-to-device access and pairs for their devices**, **Open public internet ports to their devices**. The
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

## Named join codes, person rename and Admin devices (added later)

Three flags in `CurrentConfiguration` (all `bool`, omitted when false; the
server sets each when it has an authorization document) advertise these:

- **`named_join_codes_enabled`.** `POST /v1/invitations` accepts
  `fixed_member_name: true` beside the usual request. The request must have
  `recipient_names`, no `target_member_id` and `max_uses` 1, otherwise 400. The
  signed claims carry `fixed_member_name` and need claims schema version 4. The
  request's `member_name` becomes the new person's name; the joiner chooses only
  the device name, and enrollment rejects `names.member_name` when it is present.
  Without `fixed_member_name`, a new person names themself when joining.
- **`person_rename_enabled`.** `PATCH /v1/members/{member_id}/name` with
  `{ "name": ... }` returns the membership snapshot (filtered for a Member
  caller). Allowed for the Owner (anyone), an Admin (ordinary Members) and a
  person renaming themself; others get 403, an unknown person 404. It answers
  409 while any waiting join code targets that person, because such codes carry
  the signed name: cancel them (**Cancel code** under **Waiting to join**)
  first. A request that keeps the current name changes nothing and skips that
  check. Rename relabels only; it touches no keys, peers or rules.
- **`admin_own_devices_enabled`.** An Admin may add devices to their own person
  without the **Add their own devices** permission. Device limits and
  suspension still apply.

Waiting join codes in the membership snapshot also list `issued_by_member_id`,
the person whose device created the code. It is absent for codes stored before
the server kept it.

**Name rule.** Every name a request introduces (person, device, and a new
person's name in a join code) goes through `validate_new_display_name`: trimmed
of surrounding whitespace, 1 to 64 characters after trimming (counted as
Unicode characters), no control characters, and none of the invisible or
text-direction formatting characters (soft hyphen, zero-width space, bidi
marks, overrides and isolates, U+2060 to U+206F, BOM, interlinear and tag
characters and similar; ZWJ and ZWNJ are allowed). The name in an additional-
device code that targets an existing person only has to match the stored name
under the looser `validate_display_name` (trim, 1 to 64, no control
characters), so names written by earlier versions still work.

**Compatibility.** An older server omits all three flags, so clients read them
as false and keep the previous behaviour: no named join codes, no person rename
(a person's name is chosen once), and Admins need the delegated permission for
their own devices.
