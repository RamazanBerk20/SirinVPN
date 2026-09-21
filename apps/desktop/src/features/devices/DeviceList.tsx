import {
  CaretDown,
  Desktop,
  Devices,
  DeviceMobile,
  Plus,
} from "@phosphor-icons/react";
import { useId, useState } from "react";
import { isAndroid } from "../../platform";
import { ActionMenu, type MenuAction } from "../../components/ActionMenu";
import { CopyValue } from "../../components/CopyValue";
import { canManageMember, memberAccessLabel } from "../../access";
import {
  memberLifecycleActions,
  type MemberLifecycleProps,
} from "./memberLifecycleActions";
import type {
  DeviceSummary,
  MemberSummary,
  MembershipSnapshot,
} from "../../types";

type Props = MemberLifecycleProps & {
  snapshot: MembershipSnapshot;
  accessLevel: "owner" | "admin" | "member";
  currentDeviceId?: string;
  platform?: "desktop";
  query: string;
  accessBusy: string | null;
  peerBusy: string | null;
  onNetwork?: () => void;
  onPolicy?: (member: MemberSummary) => void;
  onInvite: (member: MemberSummary) => void;
  onAccess: (member: MemberSummary) => Promise<void>;
  onTransfer: (member: MemberSummary) => Promise<void>;
  onRename: (deviceId: string, name: string) => Promise<void>;
  onRevoke: (deviceId: string, name: string) => Promise<void>;
  onPeer: (deviceId: string, name: string, enabled: boolean) => Promise<void>;
};

// Older profiles have no platform metadata. Use recognizable display names;
// an ambiguous name keeps the generic device icon rather than inventing an OS.
function deviceIcon(name: string, current: boolean) {
  if (current) return isAndroid ? DeviceMobile : Desktop;
  if (/android|iphone|ipad|phone|mobile|pixel|galaxy|tablet/i.test(name))
    return DeviceMobile;
  if (/linux|desktop|laptop|windows|macbook|computer|\bpc\b/i.test(name))
    return Desktop;
  return Devices;
}

function MemberControls({
  member,
  ...props
}: Props & { member: MemberSummary }) {
  const hasInvitation = props.snapshot.active_invitations.some(
    (invitation) => invitation.target_member_id === member.id,
  );
  if (isAndroid) {
    const actions = memberLifecycleActions(member, props);
    if (props.onPolicy && member.role !== "owner" && canManageMember(props.accessLevel, member))
      actions.unshift({ label: "Access policy", run: () => props.onPolicy?.(member) });
    if (props.accessLevel === "owner" && member.role === "member") actions.push(
      { label: member.administrator ? "Remove Admin" : "Make Admin", disabled: props.accessBusy === member.id || hasInvitation || props.memberBusy != null,
        reason: hasInvitation ? "Cancel this member’s active invitation first." : undefined, run: () => void props.onAccess(member) },
      { label: "Transfer ownership", danger: true, disabled: props.accessBusy === member.id || props.memberBusy != null || member.suspended || hasInvitation || member.devices.length === 0,
        reason: hasInvitation ? "Cancel this member’s active invitation first." : undefined, run: () => void props.onTransfer(member) },
    );
    if (canManageMember(props.accessLevel, member) || props.accessLevel === "member" && member.policy?.add_own_devices)
      actions.unshift({ label: "Add device", disabled: member.suspended || props.memberBusy != null || Boolean(member.policy?.device_limit && member.devices.length >= member.policy.device_limit), run: () => props.onInvite(member) });
    return <div className="device-member-controls"><span className="member-identity"><strong>{member.name}</strong><span className={`access-badge ${memberAccessLabel(member).toLowerCase()}`}>{memberAccessLabel(member)}</span></span>
      {actions.length > 0 && <ActionMenu label={`Member actions for ${member.name}`} actions={actions} />}
    </div>;
  }
  return (
    <div className="device-member-controls">
      <span className="member-identity">
        <strong>{member.name}</strong>
        <span
          className={`access-badge ${memberAccessLabel(member).toLowerCase()}`}
        >
          {memberAccessLabel(member)}
        </span>
      </span>
      <div className="member-actions">
        {props.onPolicy && member.role !== "owner" && canManageMember(props.accessLevel, member) &&
          <button className="text-button" onClick={() => props.onPolicy?.(member)}>Access policy</button>}
        {memberLifecycleActions(member, props).length > 0 && (
          <ActionMenu
            label={`Member actions for ${member.name}`}
            actions={memberLifecycleActions(member, props)}
          />
        )}
        {props.accessLevel === "owner" && member.role === "member" && (
          <>
            {isAndroid && hasInvitation && <p className="settings-note">Cancel this member’s active device invitation before changing their role or transferring ownership.</p>}
            <button
              className="text-button"
              disabled={
                props.accessBusy === member.id ||
                hasInvitation ||
                props.memberBusy != null
              }
              title={
                hasInvitation
                  ? "Cancel this member's active device invitation first."
                  : undefined
              }
              onClick={() => void props.onAccess(member)}
            >
              {props.accessBusy === member.id
                ? "Applying"
                : member.administrator
                  ? "Remove Admin"
                  : "Make Admin"}
            </button>
            <button
              className="text-button danger-text"
              disabled={
                props.accessBusy === member.id ||
                props.memberBusy != null ||
                member.suspended ||
                hasInvitation ||
                member.devices.length === 0
              }
              title={
                hasInvitation
                  ? "Cancel this member's active device invitation first."
                  : undefined
              }
              onClick={() => void props.onTransfer(member)}
            >
              Transfer ownership
            </button>
          </>
        )}
        {(canManageMember(props.accessLevel, member) || (props.accessLevel === "member" && member.policy?.add_own_devices)) && (
          <button
            className="text-button add-device-button"
            disabled={member.suspended || props.memberBusy != null || Boolean(member.policy?.device_limit && member.devices.length >= member.policy.device_limit)}
            onClick={() => props.onInvite(member)}
          >
            <Plus size={14} /> Add device
          </button>
        )}
      </div>
    </div>
  );
}

function DeviceRow({
  device,
  member,
  ...props
}: Props & { device: DeviceSummary; member: MemberSummary }) {
  const [expanded, setExpanded] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const id = useId();
  const current = device.id === props.currentDeviceId;
  const Icon = deviceIcon(device.name, current);
  const activity = member.suspended
    ? "Suspended"
    : current
      ? "Connected"
      : device.recent_handshake === true
        ? "Recently active"
        : device.recent_handshake === false
          ? "No recent activity"
          : "Activity unknown";
  const hint = member.suspended
    ? "This member's devices are suspended. Reactivation restores their saved identities and access."
    : current
      ? "This device's local tunnel is connected."
      : device.recent_handshake === true
        ? "Handshake within three minutes. This is not a guarantee of current connectivity."
        : device.recent_handshake === false
          ? "No recent handshake. The device may be idle or disconnected."
          : "The server did not provide activity information.";
  const manageable = canManageMember(props.accessLevel, member);
  const lastOwnerDevice =
    member.role === "owner" && member.devices.length === 1;
  const hasInvitation = props.snapshot.active_invitations.some(
    (i) => i.target_member_id === member.id,
  );
  const actions: MenuAction[] = manageable
    ? [
        {
          label: "Rename device",
          group: "Device",
          run: () => void props.onRename(device.id, device.name),
        },
        {
          label: `Add device for ${member.name}`,
          group: "Member",
          disabled: member.suspended || props.memberBusy != null,
          reason: member.suspended
            ? "Reactivate this member before adding a device."
            : undefined,
          run: () => props.onInvite(member),
        },
        ...(props.onPolicy && member.role !== "owner" ? [{ label: "Access policy", group: "Member", run: () => props.onPolicy?.(member) }] : []),
        ...memberLifecycleActions(member, props),
        {
          label: device.peer_communication_enabled
            ? "Isolate from VPN devices"
            : "Enable mutual device access",
          disabled: props.peerBusy === device.id || props.memberBusy != null,
          run: () =>
            void props.onPeer(
              device.id,
              device.name,
              Boolean(device.peer_communication_enabled),
            ),
        },
        {
          label: `Revoke ${device.name}`,
          group: "Device",
          danger: true,
          disabled: lastOwnerDevice || props.memberBusy != null,
          reason: lastOwnerDevice
            ? "The last Owner device cannot be revoked."
            : undefined,
          run: () => void props.onRevoke(device.id, device.name),
        },
      ]
    : [];
  if (props.accessLevel === "owner" && member.role === "member")
    actions.push(
      {
        label: member.administrator ? "Remove Admin" : "Make Admin",
        disabled:
          props.accessBusy === member.id ||
          hasInvitation ||
          props.memberBusy != null,
        reason: hasInvitation
          ? "Cancel this member's device invitation first."
          : undefined,
        run: () => void props.onAccess(member),
      },
      {
        label: "Transfer ownership",
        group: "Ownership",
        disabled:
          props.accessBusy === member.id ||
          hasInvitation ||
          member.suspended ||
          props.memberBusy != null,
        reason: member.suspended
          ? "Reactivate this member before transferring ownership."
          : hasInvitation
            ? "Cancel this member's device invitation first."
            : undefined,
        run: () => void props.onTransfer(member),
        danger: true,
      },
    );
  if (props.accessLevel === "member" && member.policy?.manage_own_peer_communication) actions.push({
    label: device.peer_communication_enabled ? "Isolate from VPN devices" : "Enable mutual device access",
    disabled: props.peerBusy === device.id,
    run: () => void props.onPeer(device.id, device.name, Boolean(device.peer_communication_enabled)),
  });
  if (props.onNetwork && (manageable || (props.accessLevel === "member" && member.policy?.manage_own_port_forwards)))
    actions.push({ label: "Port forwarding settings", run: props.onNetwork });
  return (
    <article
      className="device-row"
      data-expanded={expanded}
      data-suspended={Boolean(member.suspended)}
    >
      <div className="device-row-header">
        <button
          className="device-row-summary"
          aria-expanded={expanded}
          aria-controls={id}
          onClick={() => setExpanded(!expanded)}
        >
          <span className="device-icon">
            <span
              className={`device-activity ${member.suspended ? "idle" : current || device.recent_handshake === true ? "active" : device.recent_handshake === false ? "idle" : "unknown"}`}
              aria-hidden="true"
            />
            <Icon size={22} />
          </span>
          <span className="device-row-copy">
            <strong>
              {device.name}
              {current && <span className="this-device">This device</span>}
            </strong>
            <small>
              Tunnel IP:{" "}
              <span className="mono">{device.client_tunnel_address}</span> ·
              {memberAccessLabel(member)}
            </small>
          </span>
          <span className="device-activity-label">{activity}</span>
          <CaretDown size={18} className="disclosure-chevron" />
        </button>
        {actions.length > 0 && (
          <ActionMenu
            label={`Actions for ${device.name}`}
            actions={actions}
            onOpenChange={setMenuOpen}
          />
        )}
      </div>
      <div
        className="device-row-details"
        id={id}
        hidden={!expanded}
        inert={menuOpen}
      >
        <dl className="device-facts">
          {!current && (
            <div>
              <dt>Activity</dt>
              <dd>{hint}</dd>
            </div>
          )}
          <div>
            <dt>Device network access</dt>
            <dd>
              {member.suspended
                ? "Suspended. VPN, management, peer connections and forwarded ports are blocked. Reactivation restores saved access."
                : device.peer_communication_enabled
                  ? "This device can send to and receive from other VPN devices that also enable mutual access."
                  : "Isolated from other VPN devices. Internet access is allowed."}
            </dd>
          </div>
          {device.identity_fingerprint && (
            <div>
              <dt>Identity fingerprint</dt>
              <dd>
                <CopyValue
                  value={device.identity_fingerprint}
                  label={`${device.name} fingerprint`}
                  shorten
                />
              </dd>
            </div>
          )}
        </dl>
        {lastOwnerDevice && (
          <div className="owner-recovery">
            <p className="settings-note">
              The last Owner device cannot be revoked.
            </p>
            <button
              className="text-button"
              onClick={() => props.onInvite(member)}
            >
              Add another Owner device
            </button>
            {props.snapshot.members.some(
              (m) =>
                m.role === "member" && !m.suspended && m.devices.length > 0,
            ) && (
              <details>
                <summary>
                  Transfer ownership to another member{" "}
                  <CaretDown size={16} className="disclosure-chevron" />
                </summary>
                {props.snapshot.members
                  .filter(
                    (m) =>
                      m.role === "member" &&
                      !m.suspended &&
                      m.devices.length > 0,
                  )
                  .map((target) => (
                    <button
                      key={target.id}
                      className="text-button"
                      disabled={
                        Boolean(props.accessBusy) ||
                        props.memberBusy != null ||
                        props.snapshot.active_invitations.some(
                          (i) => i.target_member_id === target.id,
                        )
                      }
                      onClick={() => void props.onTransfer(target)}
                    >
                      Review transfer to {target.name}
                    </button>
                  ))}
              </details>
            )}
          </div>
        )}
      </div>
    </article>
  );
}

export function DeviceList(props: Props) {
  const query = props.query.trim().toLocaleLowerCase();
  const rows = props.snapshot.members.flatMap((member) =>
    member.devices
      .filter((device) =>
        `${member.name} ${device.name} ${device.client_tunnel_address}`
          .toLocaleLowerCase()
          .includes(query),
      )
      .map((device) => (
        <DeviceRow {...props} key={device.id} member={member} device={device} />
      )),
  );
  const emptyMembers = props.snapshot.members.filter(
    (member) =>
      member.devices.length === 0 &&
      member.name.toLocaleLowerCase().includes(query),
  );
  return (
    <div className="device-list">
      {rows}
      {emptyMembers.map((member) => (
        <details className="device-row" key={member.id}>
          <summary className="device-row-summary">
            <span className="device-icon">
              <Devices size={20} />
            </span>
            <span className="device-row-copy">
              <strong>{member.name}</strong>
              <small>
                {member.suspended
                  ? "Suspended · No devices"
                  : "No authorized devices"}
              </small>
            </span>
            <CaretDown className="disclosure-chevron" size={17} />
          </summary>
          <div className="device-row-details">
            <MemberControls {...props} member={member} />
          </div>
        </details>
      ))}
      {rows.length === 0 && emptyMembers.length === 0 && (
        <p role="status" className="device-list-empty">
          No devices match your search.
        </p>
      )}
    </div>
  );
}
