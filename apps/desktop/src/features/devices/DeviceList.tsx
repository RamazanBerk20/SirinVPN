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
import { canManageMember, memberAccessLabel, memberAccessLevel } from "../../access";
import { t } from "../../i18n";
import { Rich } from "../../i18n/Rich";
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
      actions.unshift({ label: t("devices.menu.accessPolicy"), group: t("devices.menu.group.member"), run: () => props.onPolicy?.(member) });
    if (props.accessLevel === "owner" && member.role === "member") actions.push(
      { label: t(member.administrator ? "devices.menu.removeAdmin" : "devices.menu.makeAdmin"), group: t("devices.menu.group.member"), disabled: props.accessBusy === member.id || hasInvitation || props.memberBusy != null,
        reason: hasInvitation ? t("devices.menu.cancelInvitationFirst") : undefined, run: () => void props.onAccess(member) },
      { label: t("devices.menu.transfer"), group: t("devices.menu.group.ownership"), danger: true, disabled: props.accessBusy === member.id || props.memberBusy != null || member.suspended || hasInvitation || member.devices.length === 0,
        reason: hasInvitation ? t("devices.menu.cancelInvitationFirst") : undefined, run: () => void props.onTransfer(member) },
    );
    if (canManageMember(props.accessLevel, member) || props.accessLevel === "member" && member.policy?.add_own_devices)
      actions.unshift({ label: t("devices.menu.addDevice"), group: t("devices.menu.group.member"), disabled: member.suspended || props.memberBusy != null || Boolean(member.policy?.device_limit && member.devices.length >= member.policy.device_limit), run: () => props.onInvite(member) });
    return <div className="device-member-controls"><span className="member-identity"><strong>{member.name}</strong><span className={`access-badge ${memberAccessLevel(member)}`}>{memberAccessLabel(member)}</span></span>
      {actions.length > 0 && <ActionMenu label={t("devices.menu.memberActions", { name: member.name })} title={member.name} actions={actions} />}
    </div>;
  }
  return (
    <div className="device-member-controls">
      <span className="member-identity">
        <strong>{member.name}</strong>
        <span
          className={`access-badge ${memberAccessLevel(member)}`}
        >
          {memberAccessLabel(member)}
        </span>
      </span>
      <div className="member-actions">
        {props.onPolicy && member.role !== "owner" && canManageMember(props.accessLevel, member) &&
          <button className="text-button" onClick={() => props.onPolicy?.(member)}>{t("devices.menu.accessPolicy")}</button>}
        {memberLifecycleActions(member, props).length > 0 && (
          <ActionMenu
            label={t("devices.menu.memberActions", { name: member.name })}
            title={member.name}
            actions={memberLifecycleActions(member, props)}
          />
        )}
        {props.accessLevel === "owner" && member.role === "member" && (
          <>
            <button
              className="text-button"
              disabled={
                props.accessBusy === member.id ||
                hasInvitation ||
                props.memberBusy != null
              }
              title={
                hasInvitation
                  ? t("devices.menu.cancelInvitationFirst")
                  : undefined
              }
              onClick={() => void props.onAccess(member)}
            >
              {props.accessBusy === member.id
                ? t("devices.menu.applying")
                : member.administrator
                  ? t("devices.menu.removeAdmin")
                  : t("devices.menu.makeAdmin")}
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
                  ? t("devices.menu.cancelInvitationFirst")
                  : undefined
              }
              onClick={() => void props.onTransfer(member)}
            >
              {t("devices.menu.transfer")}
            </button>
          </>
        )}
        {(canManageMember(props.accessLevel, member) || (props.accessLevel === "member" && member.policy?.add_own_devices)) && (
          <button
            className="text-button add-device-button"
            disabled={member.suspended || props.memberBusy != null || Boolean(member.policy?.device_limit && member.devices.length >= member.policy.device_limit)}
            onClick={() => props.onInvite(member)}
          >
            <Plus size={14} /> {t("devices.menu.addDevice")}
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
    ? t("devices.row.activity.suspended")
    : current
      ? t("common.state.connected")
      : device.recent_handshake === true
        ? t("devices.row.activity.recent")
        : device.recent_handshake === false
          ? t("devices.row.activity.idle")
          : t("devices.row.activity.unknown");
  // Shown only for other devices; this device's row already says it is connected.
  const hint = member.suspended
    ? t("devices.row.activityDetail.suspended")
    : device.recent_handshake === true
      ? t("devices.row.activityDetail.recent")
      : device.recent_handshake === false
        ? t("devices.row.activityDetail.idle")
        : t("devices.row.activityDetail.unknown");
  const manageable = canManageMember(props.accessLevel, member);
  const lastOwnerDevice =
    member.role === "owner" && member.devices.length === 1;
  const hasInvitation = props.snapshot.active_invitations.some(
    (i) => i.target_member_id === member.id,
  );
  const actions: MenuAction[] = manageable
    ? [
        {
          label: t("devices.menu.rename"),
          group: t("devices.menu.group.device"),
          run: () => void props.onRename(device.id, device.name),
        },
        {
          label: t("devices.menu.addDeviceFor", { name: member.name }),
          group: t("devices.menu.group.member"),
          disabled: member.suspended || props.memberBusy != null,
          reason: member.suspended
            ? t("devices.menu.reactivateFirst")
            : undefined,
          run: () => props.onInvite(member),
        },
        ...(props.onPolicy && member.role !== "owner" ? [{ label: t("devices.menu.accessPolicy"), group: t("devices.menu.group.member"), run: () => props.onPolicy?.(member) }] : []),
        ...memberLifecycleActions(member, props),
        {
          label: device.peer_communication_enabled
            ? t("devices.menu.isolate")
            : t("devices.menu.allowMutual"),
          group: t("devices.menu.group.device"),
          disabled: props.peerBusy === device.id || props.memberBusy != null,
          run: () =>
            void props.onPeer(
              device.id,
              device.name,
              Boolean(device.peer_communication_enabled),
            ),
        },
        {
          label: t("devices.menu.revoke", { name: device.name }),
          group: t("devices.menu.group.device"),
          danger: true,
          disabled: lastOwnerDevice || props.memberBusy != null,
          reason: lastOwnerDevice
            ? t("devices.row.lastOwnerDevice")
            : undefined,
          run: () => void props.onRevoke(device.id, device.name),
        },
      ]
    : [];
  if (props.accessLevel === "owner" && member.role === "member")
    actions.push(
      {
        label: t(member.administrator ? "devices.menu.removeAdmin" : "devices.menu.makeAdmin"),
        group: t("devices.menu.group.member"),
        disabled:
          props.accessBusy === member.id ||
          hasInvitation ||
          props.memberBusy != null,
        reason: hasInvitation
          ? t("devices.menu.cancelInvitationFirst")
          : undefined,
        run: () => void props.onAccess(member),
      },
      {
        label: t("devices.menu.transfer"),
        group: t("devices.menu.group.ownership"),
        disabled:
          props.accessBusy === member.id ||
          hasInvitation ||
          member.suspended ||
          props.memberBusy != null,
        reason: member.suspended
          ? t("devices.menu.reactivateFirst")
          : hasInvitation
            ? t("devices.menu.cancelInvitationFirst")
            : undefined,
        run: () => void props.onTransfer(member),
        danger: true,
      },
    );
  if (props.accessLevel === "member" && member.policy?.manage_own_peer_communication) actions.push({
    label: t(device.peer_communication_enabled ? "devices.menu.isolate" : "devices.menu.allowMutual"),
    group: t("devices.menu.group.device"),
    disabled: props.peerBusy === device.id,
    run: () => void props.onPeer(device.id, device.name, Boolean(device.peer_communication_enabled)),
  });
  if (props.onNetwork && (manageable || (props.accessLevel === "member" && member.policy?.manage_own_port_forwards)))
    actions.push({ label: t("devices.menu.portForwarding"), group: t("devices.menu.group.device"), run: props.onNetwork });
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
              {current && <span className="this-device">{t("common.noun.thisDevice")}</span>}
            </strong>
            <small>
              <Rich
                id="devices.row.subtitle"
                params={{ address: device.client_tunnel_address, role: memberAccessLabel(member) }}
                tags={{ address: (content) => <span className="mono">{content}</span> }}
              />
            </small>
          </span>
          <span className="device-activity-label">{activity}</span>
          <CaretDown size={18} className="disclosure-chevron" />
        </button>
        {actions.length > 0 && (
          <ActionMenu
            label={t("devices.menu.deviceActions", { name: device.name })}
            title={device.name}
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
          <div>
            <dt>{t("devices.row.facts.address")}</dt>
            <dd className="mono">{device.client_tunnel_address}</dd>
          </div>
          {!current && (
            <div>
              <dt>{t("devices.row.facts.activity")}</dt>
              <dd>{hint}</dd>
            </div>
          )}
          <div>
            <dt>{t("devices.row.facts.network")}</dt>
            <dd>
              {member.suspended
                ? t("devices.row.network.suspended")
                : device.peer_communication_enabled
                  ? t("devices.row.network.mutual")
                  : t("devices.row.network.isolated")}
            </dd>
          </div>
          {device.identity_fingerprint && (
            <div>
              <dt>{t("devices.row.facts.fingerprint")}</dt>
              <dd>
                <CopyValue
                  value={device.identity_fingerprint}
                  label={t("devices.row.fingerprintLabel", { name: device.name })}
                  shorten
                />
              </dd>
            </div>
          )}
        </dl>
        {lastOwnerDevice && (
          <div className="owner-recovery">
            <p className="settings-note">
              {t("devices.row.lastOwnerDevice")}
            </p>
            <button
              className="text-button"
              onClick={() => props.onInvite(member)}
            >
              {t("devices.row.addOwnerDevice")}
            </button>
            {props.snapshot.members.some(
              (m) =>
                m.role === "member" && !m.suspended && m.devices.length > 0,
            ) && (
              <details>
                <summary>
                  {t("devices.row.transferToOther")}{" "}
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
                      {t("devices.row.transferTo", { name: target.name })}
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
                  ? t("devices.row.suspendedNoDevices")
                  : t("devices.row.noDevices")}
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
          {t("devices.row.noMatches")}
        </p>
      )}
    </div>
  );
}
