import { ArrowClockwise, ArrowRight, Plus, Warning } from "@phosphor-icons/react";
import { useState } from "react";
import { api } from "../../api";
import { CopyButton } from "../../components/CopyButton";
import { CopyValue } from "../../components/CopyValue";
import { Field, InlineError } from "../../components/ui";
import { formatList, t } from "../../i18n";
import { Rich } from "../../i18n/Rich";
import { hostBitFix, invalidLocalNetworks } from "../../lib/cidr";
import { appError } from "../../lib/errors";
import type { DevicePair, DeviceSummary, MemberSummary, MembershipSnapshot, PortForwardProtocol } from "../../types";
import { devicePermissions, forwardsOf, pairCandidates, pairsOf, presence, PRESENCE_KEYS } from "./model";
import { NameField } from "./NameField";
import { deviceNameProblem } from "./names";
import { PanelSection, SidePanel } from "./SidePanel";
import type { DevicesController } from "./useDevicesController";

const MAX_FORWARDS = 32;
const GATEWAY_ADDRESS = "10.77.0.1";
/** A shell command, the same in every language. */
const FORWARDING_COMMAND = "sudo sysctl -w net.ipv4.ip_forward=1";
/** Protocol names are the same in every language. */
const protocolName = (protocol: PortForwardProtocol) => protocol.toUpperCase();
const validPort = (value: string, minimum: number) =>
  value.trim() !== "" && Number.isInteger(Number(value)) && Number(value) >= minimum && Number(value) <= 65535;
/** Splits the list the Owner typed; the VPS validates the ranges again. */
export const parseRoutes = (text: string) => text.split(/[\s,]+/).filter(Boolean);

export function DevicePanel({ controller, snapshot, person, device }: {
  controller: DevicesController; snapshot: MembershipSnapshot; person: MemberSummary; device: DeviceSummary;
}) {
  const { viewer, editable, pending } = controller;
  const can = devicePermissions(viewer, person, device);
  const current = device.id === controller.currentDeviceId;
  const state = presence(person, device);
  const key = `device:${device.id}`;
  const [error, setError] = useState<string | null>(null);
  const remove = async () => {
    const failure = await controller.change({
      key,
      confirm: current
        ? { title: t("devices.confirm.removeThis.title"), message: t("devices.confirm.removeThis.message", { server: controller.serverName }), confirm: t("devices.confirm.removeThis.action") }
        : { title: t("devices.confirm.removeDevice.title", { name: device.name }), message: t("devices.confirm.removeDevice.message", { name: device.name }), confirm: t("devices.confirm.removeDevice.action") },
      send: () => api.revokeDevice(controller.serverId, device.id),
      success: t("devices.notice.deviceRemoved", { name: device.name }),
      failure: t("devices.error.removeDevice"),
    });
    setError(failure);
    if (!failure) controller.setOverlay(null);
  };
  return <SidePanel testId="device-panel" heading={device.name}
    description={t("devices.device.summary", { name: person.name, presence: t(PRESENCE_KEYS[state]) })}
    onClose={() => controller.setOverlay(null)} busy={pending !== null}>
    {!editable && <p className="settings-note" role="status">{t("devices.panel.readOnly")}</p>}
    {can.rename && <NameField label={t("devices.device.name")} value={device.name} problem={deviceNameProblem} testId="rename-device"
      busy={pending === key} disabled={!editable || pending !== null}
      onSave={(name) => controller.change({
        key, send: () => api.renameDevice(controller.serverId, device.id, name),
        success: t("devices.notice.deviceRenamed", { name }), failure: t("devices.error.renameDevice"),
      })} />}
    <dl className="device-fact-list">
      <div><dt>{t("devices.device.owner")}</dt><dd>
        <button type="button" className="text-button" onClick={() => controller.setOverlay({ kind: "person", personId: person.id, view: "main" })}>{person.name}</button>
      </dd></div>
      <div><dt>{t("devices.device.connection")}</dt><dd>{t(device.wireguard_only ? "devices.device.wireguardApp" : "devices.device.sirinApp")}</dd></div>
      <div><dt>{t("devices.device.address")}</dt><dd className="mono" dir="ltr">{device.client_tunnel_address}</dd></div>
      <div><dt>{t("devices.device.activity")}</dt><dd>{t(PRESENCE_KEYS[state])}{current && <> <span className="this-device-chip">{t("common.noun.thisDevice")}</span></>}</dd></div>
      {device.identity_fingerprint && <div><dt>{t("devices.device.fingerprint")}</dt><dd>
        <CopyValue value={device.identity_fingerprint} label={t("devices.device.fingerprintLabel", { name: device.name })} shorten />
      </dd></div>}
    </dl>
    <PanelSection title={t("devices.network.title")}>
      <PeerToggle controller={controller} person={person} device={device} allowed={Boolean(can.peer)} />
      {can.pairs && <Pairs controller={controller} snapshot={snapshot} device={device} />}
      {!can.pairs && pairsOf(snapshot, device.id).length > 0 && <PairList snapshot={snapshot} device={device} />}
      {can.localNetworks && <LocalNetworks controller={controller} device={device} />}
      {can.portForwards && <PortForwards controller={controller} snapshot={snapshot} person={person} device={device} blocked={can.portForwards.blocked} />}
    </PanelSection>
    {can.remove && <PanelSection title={t("devices.device.removeTitle")} danger>
      <div className="danger-row">
        <p>{can.remove.blocked ?? t(current ? "devices.device.removeThisHint" : "devices.device.removeHint", { server: controller.serverName })}</p>
        <button className="primary-button danger-action" data-testid="remove-device" disabled={!editable || pending !== null || Boolean(can.remove.blocked)} onClick={() => void remove()}>
          {t(current ? "devices.device.removeThis" : "devices.device.remove")}
        </button>
      </div>
      {error && <InlineError message={error} />}
    </PanelSection>}
  </SidePanel>;
}

function PeerToggle({ controller, person, device, allowed }: { controller: DevicesController; person: MemberSummary; device: DeviceSummary; allowed: boolean }) {
  const [error, setError] = useState<string | null>(null);
  const on = Boolean(device.peer_communication_enabled);
  const toggle = async (enabled: boolean) => setError(await controller.change({
    key: `device:${device.id}`,
    send: () => api.updateDevicePeerCommunication(controller.serverId, device.id, enabled),
    success: t(enabled ? "devices.notice.peerOn" : "devices.notice.peerOff", { name: device.name }),
    failure: t("devices.error.peer"),
  }));
  return <>
    <label className="preference-row">
      <span>
        <strong>{t("devices.network.peer")}</strong>
        <small>{person.suspended ? t("devices.network.suspended", { name: person.name }) : t(on ? "devices.network.peerOn" : "devices.network.peerOff")}</small>
      </span>
      <input type="checkbox" role="switch" data-testid="peer-toggle" aria-label={t("devices.network.peer")} checked={on}
        disabled={!allowed || !controller.editable || controller.pending !== null} onChange={(event) => void toggle(event.target.checked)} />
    </label>
    {error && <InlineError message={error} />}
  </>;
}

/** "A ↔ B" or "A → B" in words, the device that starts connections first. */
function pairText(snapshot: MembershipSnapshot, deviceId: string, pair: DevicePair) {
  const names = new Map(snapshot.members.flatMap((person) => person.devices.map((device) => [device.id, device.name] as const)));
  const name = (id: string) => names.get(id) ?? t("devices.pairs.otherDevice");
  const peer = pair.device_id === deviceId ? pair.peer_device_id : pair.device_id;
  return !pair.one_way ? t("devices.pairs.bothWays", { name: name(peer) })
    : pair.device_id === deviceId ? t("devices.pairs.starts", { name: name(peer) }) : t("devices.pairs.answers", { name: name(peer) });
}

function PairList({ snapshot, device }: { snapshot: MembershipSnapshot; device: DeviceSummary }) {
  return <div className="network-subsection">
    <h4>{t("devices.pairs.title")}</h4>
    <ul className="pair-list">{pairsOf(snapshot, device.id).map((pair) => <li className="pair-row" key={`${pair.device_id}:${pair.peer_device_id}`}><span>{pairText(snapshot, device.id, pair)}</span></li>)}</ul>
  </div>;
}

type Direction = "both" | "starts" | "answers";

function Pairs({ controller, snapshot, device }: { controller: DevicesController; snapshot: MembershipSnapshot; device: DeviceSummary }) {
  const candidates = pairCandidates(controller.viewer, snapshot, device.id);
  const pairs = pairsOf(snapshot, device.id);
  const [peer, setPeer] = useState(() => candidates.find((candidate) => !pairs.some((pair) => pair.device_id === candidate.id || pair.peer_device_id === candidate.id))?.id ?? candidates[0]?.id ?? "");
  const [direction, setDirection] = useState<Direction>("both");
  const [error, setError] = useState<string | null>(null);
  const disabled = !controller.editable || controller.pending !== null;
  const peerName = candidates.find((candidate) => candidate.id === peer)?.name ?? "";
  const removable = (pair: DevicePair) => [pair.device_id, pair.peer_device_id].every((id) => id === device.id || candidates.some((candidate) => candidate.id === id));
  const add = async () => setError(await controller.change({
    key: `device:${device.id}`,
    send: () => direction === "answers" ? api.setDevicePair(controller.serverId, peer, device.id, true) : api.setDevicePair(controller.serverId, device.id, peer, direction === "starts"),
    success: t("devices.notice.pairAdded", { name: peerName }),
    failure: t("devices.error.pair"),
  }));
  const remove = async (pair: DevicePair) => setError(await controller.change({
    key: `device:${device.id}`,
    confirm: { title: t("devices.confirm.removePair.title", { name: device.name }), message: t("devices.confirm.removePair.message"), confirm: t("devices.confirm.removePair.action") },
    send: () => api.removeDevicePair(controller.serverId, pair.device_id, pair.peer_device_id),
    success: t("devices.notice.pairRemoved"),
    failure: t("devices.error.pair"),
  }));
  return <div className="network-subsection">
    <h4>{t("devices.pairs.title")}</h4>
    <p className="settings-note">{t("devices.pairs.description")}</p>
    {pairs.length > 0 && <ul className="pair-list">
      {pairs.map((pair) => <li className="pair-row" key={`${pair.device_id}:${pair.peer_device_id}`}>
        <span>{pairText(snapshot, device.id, pair)}</span>
        {removable(pair) && <button className="text-button danger-text" disabled={disabled} onClick={() => void remove(pair)}>{t("devices.pairs.remove")}</button>}
      </li>)}
    </ul>}
    {candidates.length > 0 && <form className="pair-form" onSubmit={(event) => { event.preventDefault(); void add(); }}>
      <div className="invite-form-row">
        <Field label={t("devices.pairs.peer")}>
          <select value={peer} disabled={disabled} onChange={(event) => setPeer(event.target.value)}>
            {candidates.map((candidate) => <option key={candidate.id} value={candidate.id}>{candidate.name}</option>)}
          </select>
        </Field>
        <Field label={t("devices.pairs.direction")}>
          <select value={direction} disabled={disabled} onChange={(event) => setDirection(event.target.value as Direction)}>
            <option value="both">{t("devices.pairs.option.both")}</option>
            <option value="starts">{t("devices.pairs.option.starts", { from: device.name, to: peerName })}</option>
            <option value="answers">{t("devices.pairs.option.starts", { from: peerName, to: device.name })}</option>
          </select>
        </Field>
      </div>
      <p className="settings-note">{t("devices.pairs.directionHint")}</p>
      <button className="secondary-button" type="submit" data-testid="add-pair" disabled={disabled || !peer}><Plus size={15} aria-hidden="true" />{t("devices.pairs.add")}</button>
    </form>}
    {error && <InlineError message={error} />}
  </div>;
}

function LocalNetworks({ controller, device }: { controller: DevicesController; device: DeviceSummary }) {
  const [draft, setDraft] = useState(() => (device.subnet_routes ?? []).join("\n"));
  const [error, setError] = useState<string | null>(null);
  const invalid = draft.split("\n").map((line) => line.trim()).filter((line) => line && invalidLocalNetworks(parseRoutes(line)).length > 0);
  const fix = hostBitFix(invalid, (network) => invalidLocalNetworks([network]).length === 0);
  const unchanged = parseRoutes(draft).join() === (device.subnet_routes ?? []).join();
  const disabled = !controller.editable || controller.pending !== null;
  const save = async () => {
    const routes = parseRoutes(draft);
    setError(await controller.change({
      key: `device:${device.id}`,
      send: () => api.updateDeviceSubnetRoutes(controller.serverId, device.id, routes),
      success: t(routes.length ? "devices.notice.networksSaved" : "devices.notice.networksCleared", { name: device.name }),
      failure: t("devices.error.networks"),
    }));
  };
  return <form className="network-subsection" onSubmit={(event) => { event.preventDefault(); void save(); }}>
    <h4>{t("devices.networks.title")}</h4>
    <p className="settings-note">{t("devices.networks.description", { name: device.name })}</p>
    {(device.inactive_subnet_routes?.length ?? 0) > 0 && <p className="policy-warning"><Warning size={17} weight="fill" aria-hidden="true" /> <span>{t("devices.networks.inactive", { networks: formatList(device.inactive_subnet_routes!, "unit") })}</span></p>}
    <Field label={t("devices.networks.label")} hint={t("devices.networks.hint")}
      error={!invalid.length ? undefined : fix ? t("devices.networks.hostBits", { network: fix.entry, canonical: fix.network }) : t("devices.networks.invalid", { networks: formatList(invalid, "unit") })}>
      {/* i18n-ignore: a sample network is the same in every language */}
      <textarea value={draft} dir="ltr" onChange={(event) => setDraft(event.target.value)} placeholder="192.168.1.0/24" rows={2} disabled={disabled} spellCheck={false} />
    </Field>
    {!device.wireguard_only && <div className="command-note">
      <p>{t("devices.networks.linux", { name: device.name })}</p>
      <div className="command-block" dir="ltr">
        <code>{FORWARDING_COMMAND}</code>
        <CopyButton value={FORWARDING_COMMAND} label={t("devices.networks.copyCommand")} />
      </div>
    </div>}
    {!unchanged && <button className="secondary-button" type="submit" data-testid="save-networks" disabled={disabled || invalid.length > 0}>
      {t("devices.networks.save")}
    </button>}
    {error && <InlineError message={error} />}
  </form>;
}

function PortForwards({ controller, snapshot, person, device, blocked }: {
  controller: DevicesController; snapshot: MembershipSnapshot; person: MemberSummary; device: DeviceSummary; blocked?: string;
}) {
  const [protocol, setProtocol] = useState<PortForwardProtocol>("tcp");
  const [publicPort, setPublicPort] = useState("");
  const [devicePort, setDevicePort] = useState("");
  const [error, setError] = useState<{ message: string; publicPort: boolean } | null>(null);
  const forwards = forwardsOf(snapshot, device.id);
  const total = snapshot.port_forwards?.length ?? 0;
  const full = total >= MAX_FORWARDS;
  const disabled = !controller.editable || controller.pending !== null || Boolean(blocked);
  const publicError = (error?.publicPort ? error.message : "") || (publicPort && !validPort(publicPort, 1024)
    ? Number(publicPort) < 1024 ? t("devices.ports.publicPortLow") : t("devices.ports.publicPortRange") : "");
  const deviceError = devicePort && !validPort(devicePort, 1) ? t("devices.ports.devicePortRange") : "";
  const valid = !publicError && !deviceError && validPort(publicPort, 1024) && validPort(devicePort, 1);
  const open = async () => {
    if (!valid) return;
    const port = Number(publicPort), target = Number(devicePort);
    let publicPortTaken = false;
    const failure = await controller.change({
      key: `device:${device.id}`,
      confirm: {
        title: t("devices.confirm.openPort.title", { publicPort: String(port) }),
        message: t("devices.confirm.openPort.message", { protocol: protocolName(protocol), publicPort: String(port), device: device.name, devicePort: String(target) }),
        confirm: t("devices.confirm.openPort.action"),
      },
      send: () => api.createPortForward(controller.serverId, protocol, port, device.id, target),
      success: t("devices.notice.portOpened", { port: String(port) }),
      failure: t("devices.error.openPort"),
      // The VPS names a reserved or taken public port; that failure belongs under its field.
      onError: (reason) => { publicPortTaken = appError(reason, ["port_forward_public_port"]).code === "port_forward_public_port"; return undefined; },
    });
    if (failure) {
      setError({ message: failure, publicPort: publicPortTaken });
    } else { setPublicPort(""); setDevicePort(""); setError(null); }
  };
  const close = async (forwardProtocol: PortForwardProtocol, port: number) => {
    const failure = await controller.change({
      key: `device:${device.id}`,
      confirm: { title: t("devices.confirm.closePort.title", { protocol: protocolName(forwardProtocol), publicPort: String(port) }), message: t("devices.confirm.closePort.message"), confirm: t("devices.confirm.closePort.action") },
      send: () => api.removePortForward(controller.serverId, forwardProtocol, port),
      success: t("devices.notice.portClosed", { port: String(port) }),
      failure: t("devices.error.closePort"),
    });
    setError(failure ? { message: failure, publicPort: false } : null);
  };
  return <div className="network-subsection port-forwards">
    <h4>{t("devices.ports.title")}</h4>
    {blocked && <p className="settings-note">{blocked}</p>}
    {forwards.length > 0 ? <ul className="ports-list">
      {forwards.map((forward) => <li className="ports-rule" key={`${forward.protocol}:${forward.public_port}`}>
        <span className={`ports-protocol ${forward.protocol}`}>{protocolName(forward.protocol)}</span>
        <span className="ports-rule-copy">
          <span className="ports-route mono" dir="ltr">{forward.public_port}<ArrowRight size={14} aria-hidden="true" />{device.client_tunnel_address}:{forward.device_port}</span>
          {person.suspended && <small>{t("devices.ports.paused")}</small>}
        </span>
        <button className="text-button danger-text" disabled={!controller.editable || controller.pending !== null}
          aria-label={t("devices.ports.closeLabel", { protocol: protocolName(forward.protocol), publicPort: String(forward.public_port), devicePort: String(forward.device_port) })}
          onClick={() => void close(forward.protocol, forward.public_port)}>{t("devices.ports.close")}</button>
      </li>)}
    </ul> : <p className="settings-note">{t("devices.ports.none")}</p>}
    {!blocked && <form className="ports-form" onSubmit={(event) => { event.preventDefault(); void open(); }}>
      <p className="ports-warning"><Warning size={18} weight="fill" aria-hidden="true" /> <span>{t("devices.ports.exposure")}</span></p>
      <div className="ports-form-fields">
        <Field label={t("devices.ports.protocol")}>
          <select value={protocol} disabled={disabled} onChange={(event) => { setProtocol(event.target.value as PortForwardProtocol); setError(null); }}>
            <option value="tcp">{protocolName("tcp")}</option>
            <option value="udp">{protocolName("udp")}</option>
          </select>
        </Field>
        <Field label={t("devices.ports.publicPort")} hint={t("devices.ports.publicPortHint")} error={publicError || undefined}>
          <input type="number" min="1024" max="65535" inputMode="numeric" value={publicPort} disabled={disabled} onChange={(event) => { setPublicPort(event.target.value); setError(null); }} />
        </Field>
        <Field label={t("devices.ports.devicePort")} hint={t("devices.ports.devicePortHint")} error={deviceError || undefined}>
          <input type="number" min="1" max="65535" inputMode="numeric" value={devicePort} disabled={disabled} onChange={(event) => setDevicePort(event.target.value)} />
        </Field>
      </div>
      <div className="ports-form-footer">
        <p className="ports-preview">
          {valid ? <Rich id="devices.ports.preview" params={{ protocol: protocolName(protocol), publicPort: String(Number(publicPort)), device: device.name, devicePort: String(Number(devicePort)) }}
            tags={{ strong: (content) => <strong>{content}</strong> }} />
            : full ? t("devices.ports.full", { count: MAX_FORWARDS }) : t("devices.ports.used", { count: total, max: MAX_FORWARDS })}
        </p>
        <button className="secondary-button" type="submit" data-testid="open-port" disabled={disabled || !valid || full}>
          {controller.pending === `device:${device.id}` ? <ArrowClockwise className="spin" size={16} aria-hidden="true" /> : <Plus size={16} weight="bold" aria-hidden="true" />}
          {t("devices.ports.open")}
        </button>
      </div>
      {error && !error.publicPort && <InlineError message={error.message} />}
      <p className="settings-note"><Rich id="devices.ports.visitorAddress" params={{ address: GATEWAY_ADDRESS }} tags={{ address: (content) => <span className="mono" dir="ltr">{content}</span> }} /></p>
    </form>}
  </div>;
}
