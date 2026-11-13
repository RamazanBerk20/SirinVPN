import { CaretRight, Clock, Desktop, DeviceMobile, Devices, Plus, Prohibit } from "@phosphor-icons/react";
import { useId } from "react";
import { personRole, roleLabel } from "../../access";
import { formatDateTime, intlLocale, t } from "../../i18n";
import { isAndroid } from "../../platform";
import type { DeviceSummary, MemberSummary, MembershipSnapshot } from "../../types";
import { addDeviceGate, deviceSummary, presence, PRESENCE_KEYS } from "./model";
import type { DevicesController } from "./useDevicesController";

/** The platform the device reported wins; older servers and WireGuard devices fall back to the name. */
export function deviceIcon({ name, platform }: Pick<DeviceSummary, "name" | "platform">, current: boolean) {
  if (platform === "android") return DeviceMobile;
  if (platform === "linux" || platform === "windows") return Desktop;
  if (current) return isAndroid ? DeviceMobile : Desktop;
  if (/android|iphone|ipad|phone|mobile|pixel|galaxy|tablet/i.test(name)) return DeviceMobile;
  if (/linux|desktop|laptop|windows|macbook|computer|\bpc\b/i.test(name)) return Desktop;
  return Devices;
}

const initial = (name: string) => [...name.trim()].slice(0, 1).join("").toLocaleUpperCase(intlLocale()) || "?";

/** Suspended and the limits worth seeing without opening the person. */
export function PersonChips({ person }: { person: MemberSummary }) {
  const policy = person.role === "owner" ? undefined : person.policy;
  const chips: { key: string; text: string; tone: string; icon?: "clock" | "paused" }[] = [];
  if (person.suspended) chips.push({ key: "suspended", text: t("devices.person.suspended"), tone: "danger", icon: "paused" });
  if (policy?.weekly_access.length) chips.push({ key: "hours", text: t("devices.person.limitedHours"), tone: "neutral", icon: "clock" });
  if (policy?.expires_at_unix) {
    const past = policy.expires_at_unix * 1000 <= Date.now();
    const date = formatDateTime(new Date(policy.expires_at_unix * 1000), { dateStyle: "medium" });
    chips.push({ key: "expires", text: t(past ? "devices.person.expired" : "devices.person.expires", { date }), tone: past ? "warning" : "neutral" });
  }
  if (chips.length === 0) return null;
  return <span className="person-chips">
    {chips.map((chip) => <span key={chip.key} className={`status-chip ${chip.tone}`}>
      {chip.icon === "clock" && <Clock size={13} aria-hidden="true" />}
      {chip.icon === "paused" && <Prohibit size={13} weight="bold" aria-hidden="true" />}
      {chip.text}
    </span>)}
  </span>;
}

/** A person's devices: each row opens the device's panel. */
export function DeviceRows({ controller, snapshot, person, devices }: {
  controller: DevicesController; snapshot: MembershipSnapshot; person: MemberSummary; devices: DeviceSummary[];
}) {
  return <ul className="member-device-list">
    {devices.map((device) => {
      const current = device.id === controller.currentDeviceId;
      const Icon = deviceIcon(device, current);
      const state = presence(person, device);
      return <li key={device.id}>
        <button type="button" className="device-item device-row-button" data-state={state} data-testid="open-device"
          onClick={() => controller.setOverlay({ kind: "device", deviceId: device.id })}>
          <span className="device-tile">
            <span className={`device-dot ${state}`} aria-hidden="true" />
            <Icon size={22} aria-hidden="true" />
          </span>
          <span className="device-item-copy">
            <strong>
              <span dir="auto">{device.name}</span>
              {current && <span className="this-device-chip">{t("common.noun.thisDevice")}</span>}
            </strong>
            <small>{deviceSummary(snapshot, device)}</small>
          </span>
          <span className={`device-status ${state}`}>{t(PRESENCE_KEYS[state])}</span>
          <CaretRight className="row-chevron mirror-rtl" size={16} aria-hidden="true" />
        </button>
      </li>;
    })}
  </ul>;
}

/** One person and their devices. "My devices" is the viewer's own group. */
export function PersonGroup({ controller, snapshot, person, devices, mine }: {
  controller: DevicesController; snapshot: MembershipSnapshot; person: MemberSummary; devices: DeviceSummary[]; mine: boolean;
}) {
  const heading = useId();
  const role = personRole(person);
  const gate = controller.editable ? addDeviceGate(controller.viewer, person) : null;
  const limit = person.role === "owner" ? null : person.policy?.device_limit;
  const count = limit ? t("devices.person.devicesOfLimit", { count: person.devices.length, limit }) : t("devices.count.devices", { count: person.devices.length });
  return (
    <section className="member-group" aria-labelledby={heading} data-suspended={Boolean(person.suspended)} data-testid={mine ? "my-devices" : "person-group"}>
      <header className="member-group-header">
        <span className={`member-avatar ${role}`} aria-hidden="true">{initial(person.name)}</span>
        <div className="member-group-title">
          <h3 id={heading}>
            <button type="button" className="person-link" data-testid="open-person"
              onClick={() => controller.setOverlay({ kind: "person", personId: person.id, view: "main" })}>
              {mine ? t("devices.page.mine") : person.name}
            </button>
          </h3>
          <p className="member-group-meta">
            {mine && <span dir="auto">{person.name}</span>}
            <span className={`access-badge ${role}`}>{roleLabel(role)}</span>
            <span>{count}</span>
            <PersonChips person={person} />
          </p>
        </div>
        {gate && !gate.blocked && <div className="member-group-actions">
          <button type="button" className="secondary-button compact-button" data-testid="add-device-for" disabled={controller.pending !== null}
            onClick={() => controller.setOverlay({ kind: "add", preset: mine ? { kind: "self" } : { kind: "person", personId: person.id } })}>
            <Plus size={15} weight="bold" aria-hidden="true" />
            <span>{mine ? t("devices.page.addMine") : t("devices.page.addFor", { name: person.name })}</span>
          </button>
        </div>}
      </header>
      {gate?.blocked && <p className="member-group-reason">{gate.blocked}</p>}
      {mine && !gate && controller.editable && controller.viewer.role === "admin" && <p className="member-group-reason">{t("devices.page.adminOwnDevices")}</p>}
      {person.devices.length === 0
        ? <p className="member-group-empty">{t(person.suspended ? "devices.person.noDevicesSuspended" : "devices.person.noDevices")}</p>
        : <DeviceRows controller={controller} snapshot={snapshot} person={person} devices={devices} />}
    </section>
  );
}
