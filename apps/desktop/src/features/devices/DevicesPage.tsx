import { ArrowClockwise, DeviceMobile, LockKey, MagnifyingGlass, Plus, UserPlus, Wrench, X } from "@phosphor-icons/react";
import { useState } from "react";
import { InlineError } from "../../components/ui";
import { foldText, formatDateTime, t } from "../../i18n";
import type { MemberSummary, MembershipSnapshot } from "../../types";
import { AddDeviceWizard } from "./AddDeviceWizard";
import { DevicePanel } from "./DevicePanel";
import { JoinCodes } from "./JoinCodes";
import { addDeviceEntry, findDevice, groupPeople, type PageState } from "./model";
import { PersonGroup } from "./PersonGroup";
import { PersonPanel } from "./PersonPanel";
import { useDevicesController, type DevicesController, type DevicesProps } from "./useDevicesController";

/** Search pays off once the list no longer fits at a glance. */
const SEARCH_FROM = 6;

const savedTime = (at: number) => formatDateTime(new Date(at), { dateStyle: "medium", timeStyle: "short" });

/** What the page says above the list, for every state but "ready". */
function Notice({ page, controller, onConnect, onOpenHome }: { page: PageState; controller: DevicesController; onConnect?: () => void; onOpenHome?: () => void }) {
  switch (page.kind) {
    case "ready": return null;
    case "disconnected": return <div className="devices-notice" role="status">
      <LockKey size={20} aria-hidden="true" />
      <p>{page.saved ? t("devices.page.disconnectedSaved", { time: savedTime(page.saved.at) }) : t("devices.page.disconnected")}</p>
      {onConnect ? <button className="primary-button" data-testid="connect" onClick={onConnect}>{t("devices.page.connect")}</button>
        : onOpenHome && <button className="secondary-button" onClick={onOpenHome}>{t("devices.page.openHome")}</button>}
    </div>;
    case "loading": return <div className="devices-notice" role="status"><ArrowClockwise className="spin" size={20} aria-hidden="true" /><p>{t("devices.page.loading")}</p></div>;
    case "stale": return <>
      <InlineError message={page.error} onRetry={() => void controller.refresh()} retryDisabled={page.refreshing} />
      <p className="settings-note" role="status">{t("devices.page.stale", { time: savedTime(page.at) })}</p>
    </>;
    case "failed": return <InlineError message={page.error} onRetry={() => void controller.refresh()} retryDisabled={page.refreshing} />;
    case "unsupported": return <div className="devices-notice" role="status"><Wrench size={20} aria-hidden="true" /><p>{t(controller.viewer.role === "owner" ? "devices.page.unsupportedOwner" : "devices.page.unsupported")}</p></div>;
  }
}

/** While nothing was ever read: this device alone, from the saved profile. */
function placeholder(controller: DevicesController): MembershipSnapshot | null {
  if (!controller.currentDeviceId) return null;
  return { members: [{ id: "", name: t("devices.page.you"), role: controller.viewer.role === "owner" ? "owner" : "member", administrator: controller.viewer.role === "admin",
    devices: [{ id: controller.currentDeviceId, member_id: "", name: t("devices.page.unnamed"), client_tunnel_address: "" }] }], active_invitations: [] };
}

function matches(person: MemberSummary, query: string) {
  const named = foldText(person.name).includes(query);
  const devices = named ? person.devices : person.devices.filter((device) => foldText(`${device.name} ${device.client_tunnel_address}`).includes(query));
  return named || devices.length > 0 ? devices : null;
}

export function DevicesPage(props: DevicesProps & { onConnect?: () => void; onOpenHome?: () => void }) {
  const controller = useDevicesController(props);
  const { page, viewer, overlay, editable } = controller;
  const [query, setQuery] = useState("");
  const snapshot = controller.snapshot ?? (page.kind === "disconnected" ? placeholder(controller) : null);
  const entry = editable && snapshot ? addDeviceEntry(viewer, snapshot) : null;
  const { self, others } = snapshot ? groupPeople(snapshot, props.profile.device_id) : { self: null, others: [] };
  const deviceCount = snapshot?.members.reduce((count, person) => count + person.devices.length, 0) ?? 0;
  const needle = foldText(query.trim());
  const shown = (person: MemberSummary) => needle ? matches(person, needle) : person.devices;
  const lonely = editable && snapshot && !needle && others.length === 0 && deviceCount <= 1;
  const add = (preset: Parameters<DevicesController["setOverlay"]>[0]) => controller.setOverlay(preset);
  const panel = (() => {
    if (!overlay || !snapshot) return null;
    if (overlay.kind === "add") return editable ? <AddDeviceWizard controller={controller} snapshot={snapshot} preset={overlay.preset} /> : null;
    if (overlay.kind === "person") {
      const person = snapshot.members.find((entry) => entry.id === overlay.personId);
      return person ? <PersonPanel key={`${person.id}:${overlay.view}`} controller={controller} snapshot={snapshot} person={person} view={overlay.view} /> : null;
    }
    const found = findDevice(snapshot, overlay.deviceId);
    return found ? <DevicePanel key={found.device.id} controller={controller} snapshot={snapshot} person={found.person} device={found.device} /> : null;
  })();
  return (
    <section className="access-section devices-page" data-state={page.kind} data-testid="devices-page" aria-busy={page.kind === "loading" || ("refreshing" in page && page.refreshing)}>
      <div className="devices-heading">
        {snapshot && page.kind !== "loading" ? <p className="devices-summary">
          {t("common.separator.pair", { first: t("devices.count.people", { count: snapshot.members.length }), second: t("devices.count.devices", { count: deviceCount }) })}
        </p> : <span />}
        <div className="devices-heading-actions">
          {props.connected && <button className="icon-button" data-testid="refresh" disabled={page.kind === "loading" || ("refreshing" in page && page.refreshing)}
            aria-label={t("devices.page.refresh")} title={t("devices.page.refresh")} onClick={() => void controller.refresh()}>
            <ArrowClockwise size={17} aria-hidden="true" className={"refreshing" in page && page.refreshing ? "spin" : undefined} />
          </button>}
          {entry?.any && <button className="primary-button" data-testid="add-device" disabled={controller.pending !== null} onClick={() => add({ kind: "add", preset: entry.mine && !entry.mine.blocked && entry.people.length === 0 && entry.roles.length === 0 ? { kind: "self" } : null })}>
            <Plus size={16} weight="bold" aria-hidden="true" /> {t("devices.page.add")}
          </button>}
        </div>
      </div>
      {entry && !entry.any && <p className="settings-note" data-testid="add-device-reason">{entry.reason}</p>}
      <Notice page={page} controller={controller} onConnect={props.onConnect} onOpenHome={props.onOpenHome} />
      {snapshot && page.kind !== "loading" && <>
        {deviceCount >= SEARCH_FROM && <div className="devices-toolbar">
          <label className="devices-search">
            <MagnifyingGlass size={17} aria-hidden="true" />
            <span className="sr-only">{t("devices.page.search")}</span>
            <input type="search" placeholder={t("devices.page.searchPlaceholder")} value={query} onChange={(event) => setQuery(event.target.value)} />
            {query && <button type="button" className="icon-button" aria-label={t("devices.page.clearSearch")} onClick={() => setQuery("")}><X size={16} aria-hidden="true" /></button>}
          </label>
        </div>}
        <div className="member-groups">
          {self && shown(self) && <PersonGroup controller={controller} snapshot={snapshot} person={self} devices={shown(self)!} mine />}
          {others.map((person) => {
            const devices = shown(person);
            return devices && <PersonGroup key={person.id} controller={controller} snapshot={snapshot} person={person} devices={devices} mine={false} />;
          })}
          {needle && !(self && shown(self)) && others.every((person) => !shown(person)) && <div className="devices-empty" role="status">
            <MagnifyingGlass size={22} aria-hidden="true" />
            <p>{t("devices.page.noMatches", { query: query.trim() })}</p>
            <button className="secondary-button" onClick={() => setQuery("")}>{t("devices.page.clearSearch")}</button>
          </div>}
        </div>
        {lonely && entry && <div className="devices-next-step" data-testid="empty-state">
          <div>
            <strong>{t("devices.empty.title")}</strong>
            <p>{t("devices.empty.body")}</p>
            <div className="empty-choices">
              {entry.mine && <button className="secondary-button" data-testid="empty-add-mine" disabled={Boolean(entry.mine.blocked)} onClick={() => add({ kind: "add", preset: { kind: "self" } })}>
                <DeviceMobile size={18} aria-hidden="true" />{t("devices.empty.mine")}
              </button>}
              {entry.roles.length > 0 && <button className="secondary-button" data-testid="empty-add-someone" onClick={() => add({ kind: "add", preset: { kind: "new" } })}>
                <UserPlus size={18} aria-hidden="true" />{t("devices.empty.someone")}
              </button>}
            </div>
            {!entry.mine && entry.roles.length === 0 && <p className="settings-note">{t("devices.page.cannotAdd")}</p>}
          </div>
        </div>}
        {snapshot.active_invitations.length > 0 && <JoinCodes codes={snapshot.active_invitations} snapshot={snapshot} viewer={viewer} controller={controller} />}
      </>}
      {panel}
    </section>
  );
}
