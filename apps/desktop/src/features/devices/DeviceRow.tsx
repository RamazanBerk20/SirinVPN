import { CaretDown, Desktop, Devices, DeviceMobile } from "@phosphor-icons/react";
import { useId, useState } from "react";
import { isAndroid } from "../../platform";
import { ActionMenu, type MenuAction } from "../../components/ActionMenu";
import { CopyValue } from "../../components/CopyValue";
import { canManageMember, canManagePeerCommunication } from "../../access";
import { pairSummaries } from "./DevicePairsDialog";
import { managedDevices, type MemberActionProps } from "./memberLifecycleActions";
import { t } from "../../i18n";
import type { DeviceSummary, MemberSummary } from "../../types";

export type DeviceRowProps = MemberActionProps & {
  currentDeviceId?: string;
  peerBusy: string | null;
  onNetwork?: () => void;
  /** Only the Owner shares local networks, and only from their own devices. */
  onSubnetRoutes?: (device: DeviceSummary) => void;
  onPairs?: (device: DeviceSummary) => void;
  onRename: (deviceId: string, name: string) => void;
  onRevoke: (deviceId: string, name: string) => Promise<void>;
  onPeer: (deviceId: string, name: string, enabled: boolean) => Promise<void>;
};

// Older profiles have no platform metadata. Use recognizable display names;
// an ambiguous name keeps the generic device icon rather than inventing an OS.
function deviceIcon(name: string, current: boolean) {
  if (current) return isAndroid ? DeviceMobile : Desktop;
  if (/android|iphone|ipad|phone|mobile|pixel|galaxy|tablet/i.test(name)) return DeviceMobile;
  if (/linux|desktop|laptop|windows|macbook|computer|\bpc\b/i.test(name)) return Desktop;
  return Devices;
}

/** One device under its member: what it is and how it is doing, with the details one click away. */
export function DeviceRow({ device, member, ...props }: DeviceRowProps & { device: DeviceSummary; member: MemberSummary }) {
  const [expanded, setExpanded] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const id = useId();
  const current = device.id === props.currentDeviceId;
  const Icon = deviceIcon(device.name, current);
  const state = member.suspended ? "suspended" : current || device.recent_handshake === true ? "active" : device.recent_handshake === false ? "idle" : "unknown";
  const activity = member.suspended
    ? t("devices.row.activity.suspended")
    : current
      ? t("common.state.connected")
      : t(state === "active" ? "devices.row.activity.recent" : state === "idle" ? "devices.row.activity.idle" : "devices.row.activity.unknown");
  const manageable = canManageMember(props.accessLevel, member);
  const lastOwnerDevice = member.role === "owner" && !device.wireguard_only && managedDevices(member).length === 1;
  const pairs = pairSummaries(props.snapshot, device.id);
  const routes = [...new Set([...(device.subnet_routes ?? []), ...(device.inactive_subnet_routes ?? [])])];
  const reachable = Boolean(device.peer_communication_enabled) || pairs.length > 0;
  const ownPeer = props.accessLevel === "member" && Boolean(member.policy?.manage_own_peer_communication);
  const actions: MenuAction[] = [];
  if (manageable) actions.push({ label: t("devices.menu.rename"), run: () => props.onRename(device.id, device.name) });
  if (manageable || ownPeer) actions.push({
    label: t(device.peer_communication_enabled ? "devices.menu.isolate" : "devices.menu.allowMutual"),
    disabled: props.peerBusy === device.id || props.memberBusy != null,
    run: () => void props.onPeer(device.id, device.name, Boolean(device.peer_communication_enabled)),
  });
  if (props.onPairs && canManagePeerCommunication(props.accessLevel, member))
    actions.push({ label: t("devices.menu.pairs"), disabled: props.memberBusy != null, run: () => props.onPairs?.(device) });
  if (props.onSubnetRoutes && props.accessLevel === "owner" && member.role === "owner")
    actions.push({ label: t("devices.menu.localNetworks"), run: () => props.onSubnetRoutes?.(device) });
  if (props.onNetwork && (manageable || (props.accessLevel === "member" && member.policy?.manage_own_port_forwards)))
    actions.push({ label: t("devices.menu.portForwarding"), run: props.onNetwork });
  if (manageable) actions.push({
    label: t("devices.menu.revoke", { name: device.name }),
    danger: true,
    disabled: lastOwnerDevice || props.memberBusy != null,
    reason: lastOwnerDevice ? t("devices.row.lastOwnerDevice") : undefined,
    run: () => void props.onRevoke(device.id, device.name),
  });
  return (
    <article className="device-item" data-expanded={expanded} data-state={state}>
      <div className="device-item-header">
        <button className="device-item-summary" aria-expanded={expanded} aria-controls={id} onClick={() => setExpanded(!expanded)}>
          <span className="device-tile">
            <span className={`device-dot ${state}`} aria-hidden="true" />
            <Icon size={22} />
          </span>
          <span className="device-item-copy">
            <strong>
              {device.name}
              {current && <span className="this-device-chip">{t("common.noun.thisDevice")}</span>}
            </strong>
            <small>
              <span className="mono">{device.client_tunnel_address}</span>
              {device.wireguard_only && <span>{t("devices.row.wireguardShort")}</span>}
            </small>
          </span>
          <span className={`device-status ${state}`}>{activity}</span>
          <CaretDown size={18} className="disclosure-chevron" aria-hidden="true" />
        </button>
        {actions.length > 0 && (
          <ActionMenu label={t("devices.menu.deviceActions", { name: device.name })} title={device.name} actions={actions} onOpenChange={setMenuOpen} />
        )}
      </div>
      <div className="device-item-details" id={id} hidden={!expanded} inert={menuOpen}>
        <dl className="device-fact-list">
          <div>
            <dt>{t("devices.row.facts.network")}</dt>
            <dd>
              {member.suspended
                ? t("devices.row.network.suspended")
                : device.peer_communication_enabled
                  ? t("devices.row.network.mutual")
                  : pairs.length > 0
                    ? t("devices.row.network.paired")
                    : t("devices.row.network.isolated")}
            </dd>
          </div>
          {pairs.length > 0 && (
            <div>
              <dt>{t("devices.row.facts.pairs")}</dt>
              <dd>{pairs.map((pair) => pair.text).join("; ")}</dd>
            </div>
          )}
          {routes.length > 0 && (
            <div>
              <dt>{t("devices.row.facts.localNetworks")}</dt>
              <dd>
                <ul className="network-chips">
                  {routes.map((route) => {
                    const inactive = device.inactive_subnet_routes?.includes(route);
                    return <li key={route}>
                      <span className="mono">{route}</span>
                      <span className={`status-chip ${inactive ? "warning" : "positive"}`}>{t(inactive ? "devices.row.networkInactive" : "devices.row.networkActive")}</span>
                    </li>;
                  })}
                </ul>
                {Boolean(device.inactive_subnet_routes?.length) && <p className="device-fact-note">{t("devices.row.networkInactiveHint")}</p>}
                {!reachable && !member.suspended && <p className="device-fact-note">{t("devices.row.networksUnreachable", { name: device.name })}</p>}
              </dd>
            </div>
          )}
          {device.wireguard_only && (
            <div>
              <dt>{t("devices.row.facts.connection")}</dt>
              <dd>{t("devices.row.wireguardOnly")}</dd>
            </div>
          )}
          {device.identity_fingerprint && (
            <div>
              <dt>{t("devices.row.facts.fingerprint")}</dt>
              <dd>
                <CopyValue value={device.identity_fingerprint} label={t("devices.row.fingerprintLabel", { name: device.name })} shorten />
              </dd>
            </div>
          )}
        </dl>
        {lastOwnerDevice && manageable && (
          <div className="owner-device-note">
            <p><strong>{t("devices.row.lastOwnerDevice")}</strong> {t("devices.row.lastOwnerHelp")}</p>
            <button className="secondary-button" disabled={member.suspended || props.memberBusy != null} onClick={() => props.onInvite(member)}>{t("devices.row.addOwnerDevice")}</button>
          </div>
        )}
      </div>
    </article>
  );
}
