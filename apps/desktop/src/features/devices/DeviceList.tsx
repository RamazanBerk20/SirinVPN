import { Clock, MagnifyingGlass, Plus, Prohibit } from "@phosphor-icons/react";
import { useId } from "react";
import { isAndroid } from "../../platform";
import { ActionMenu } from "../../components/ActionMenu";
import { memberAccessLabel, memberAccessLevel } from "../../access";
import { formatDateTime, t } from "../../i18n";
import { DeviceRow, type DeviceRowProps } from "./DeviceRow";
import { addDeviceState, memberActions } from "./memberLifecycleActions";
import type { MemberSummary } from "../../types";

type Props = DeviceRowProps & {
  platform?: "desktop";
  query: string;
  onClearSearch?: () => void;
};

const initials = (name: string) => [...name.trim()].slice(0, 1).join("").toLocaleUpperCase() || "?";

/** Limits worth seeing without opening the policy: hours, expiry and delegated invitations. */
function policyChips(member: MemberSummary) {
  const policy = member.policy;
  if (member.role === "owner" || !policy) return [];
  const chips: { key: string; text: string; tone?: "warning" }[] = [];
  if (policy.weekly_access.length) chips.push({ key: "hours", text: t("devices.member.limitedHours") });
  if (policy.expires_at_unix) {
    const past = policy.expires_at_unix * 1000 <= Date.now();
    const date = formatDateTime(new Date(policy.expires_at_unix * 1000), { dateStyle: "medium" });
    chips.push({ key: "expires", text: t(past ? "devices.member.expired" : "devices.member.expires", { date }), tone: past ? "warning" : undefined });
  }
  if (policy.invite_members) chips.push({ key: "invite", text: t("devices.member.canInvite") });
  return chips;
}

function MemberGroup({ member, visible, ...props }: Props & { member: MemberSummary; visible: MemberSummary["devices"] }) {
  const heading = useId();
  const level = memberAccessLevel(member);
  const add = addDeviceState(member, props);
  // Android has no room in the header for a button, so adding a device is the first menu item there.
  const actions = memberActions(member, props, isAndroid);
  const limit = member.policy?.device_limit;
  return (
    <section className="member-group" aria-labelledby={heading} data-suspended={Boolean(member.suspended)}>
      <header className="member-group-header">
        <span className={`member-avatar ${level}`} aria-hidden="true">{initials(member.name)}</span>
        <div className="member-group-title">
          <h3 id={heading}>{member.name}</h3>
          <p className="member-group-meta">
            <span className={`access-badge ${level}`}>{memberAccessLabel(member)}</span>
            {member.suspended && <span className="status-chip danger"><Prohibit size={13} weight="bold" aria-hidden="true" />{t("devices.member.suspended")}</span>}
            <span>{limit && member.role !== "owner"
              ? t("devices.member.devicesOfLimit", { count: member.devices.length, limit })
              : t("devices.member.devices", { count: member.devices.length })}</span>
            {policyChips(member).map((chip) => <span key={chip.key} className={`status-chip ${chip.tone ?? "neutral"}`}>
              {chip.key === "hours" && <Clock size={13} aria-hidden="true" />}{chip.text}
            </span>)}
          </p>
        </div>
        <div className="member-group-actions">
          {!isAndroid && add.allowed && (
            <button className="secondary-button compact-button" aria-label={t("devices.menu.addDeviceFor", { name: member.name })}
              disabled={add.disabled} title={add.reason}
              onClick={() => props.onInvite(member)}>
              <Plus size={15} weight="bold" /> {t("devices.menu.addDevice")}
            </button>
          )}
          {actions.length > 0 && <ActionMenu label={t("devices.menu.memberActions", { name: member.name })} title={member.name} actions={actions} />}
        </div>
      </header>
      {!isAndroid && add.allowed && add.reason && member.devices.length > 0 && <p className="member-group-reason">{add.reason}</p>}
      {member.devices.length === 0 ? (
        <p className="member-group-empty">{t(member.suspended ? "devices.member.noDevicesSuspended" : "devices.member.noDevices")}</p>
      ) : (
        <div className="member-device-list">
          {visible.map((device) => <DeviceRow {...props} key={device.id} member={member} device={device} />)}
        </div>
      )}
    </section>
  );
}

/** Devices grouped under the member they belong to, so a member action never surprises another device. */
export function DeviceList(props: Props) {
  const query = props.query.trim().toLocaleLowerCase();
  const groups = props.snapshot.members.flatMap((member) => {
    const named = member.name.toLocaleLowerCase().includes(query);
    const visible = named ? member.devices : member.devices.filter((device) =>
      `${device.name} ${device.client_tunnel_address}`.toLocaleLowerCase().includes(query));
    return named || visible.length > 0 ? [{ member, visible }] : [];
  });
  return (
    <div className="member-groups">
      {groups.map(({ member, visible }) => <MemberGroup {...props} key={member.id} member={member} visible={visible} />)}
      {groups.length === 0 && (
        <div className="devices-empty" role="status">
          <MagnifyingGlass size={22} aria-hidden="true" />
          <p>{t("devices.panel.noMatches", { query: props.query.trim() })}</p>
          {props.onClearSearch && <button className="secondary-button" onClick={props.onClearSearch}>{t("devices.panel.clearSearch")}</button>}
        </div>
      )}
    </div>
  );
}
