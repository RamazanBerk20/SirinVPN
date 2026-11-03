import { ArrowClockwise, ArrowRight, Plus, Warning, Wrench } from "@phosphor-icons/react";
import { type FormEvent } from "react";
import { canManagePortForwards } from "../../access";
import { Busy } from "../../components/OperationResult";
import { Field } from "../../components/ui";
import { type MembershipSnapshot, type PortForwardProtocol } from "../../types";
import { t } from "../../i18n";
import { Rich } from "../../i18n/Rich";

const MAX_FORWARDS = 32;
const GATEWAY_ADDRESS = "10.77.0.1";
/** Protocol names are the same in every language. */
const protocolName = (protocol: PortForwardProtocol) => protocol.toUpperCase();
const validPort = (value: string, minimum: number) =>
  value.trim() !== "" && Number.isInteger(Number(value)) && Number(value) >= minimum && Number(value) <= 65535;

export function PortForwardPanel({
  snapshot,
  accessLevel,
  available,
  protocol,
  publicPort,
  deviceId,
  devicePort,
  busy,
  onProtocolChange,
  onPublicPortChange,
  onDeviceChange,
  onDevicePortChange,
  onCreate,
  onRemove,
  onAddDevice,
  serverError,
}: {
  onAddDevice?: () => void;
  serverError?: string;
  snapshot: MembershipSnapshot;
  accessLevel: "owner" | "admin" | "member";
  available: boolean;
  protocol: PortForwardProtocol;
  publicPort: string;
  deviceId: string;
  devicePort: string;
  busy: string | null;
  onProtocolChange: (protocol: PortForwardProtocol) => void;
  onPublicPortChange: (port: string) => void;
  onDeviceChange: (deviceId: string) => void;
  onDevicePortChange: (port: string) => void;
  onCreate: (event: FormEvent<HTMLFormElement>) => Promise<void>;
  onRemove: (protocol: PortForwardProtocol, publicPort: number) => Promise<void>;
}) {
  const targets = snapshot.members.flatMap((member) =>
    !member.suspended && canManagePortForwards(accessLevel, member)
      ? member.devices.map((device) => ({ member, device }))
      : [],
  );
  const selectedDeviceId = targets.some(({ device }) => device.id === deviceId) ? deviceId : targets[0]?.device.id || "";
  const forwards = snapshot.port_forwards ?? [];
  const full = forwards.length >= MAX_FORWARDS;
  const publicError = serverError || (publicPort && !validPort(publicPort, 1024)
    ? Number(publicPort) < 1024 ? t("devices.ports.publicPortLow") : t("devices.ports.publicPortRange") : "");
  const deviceError = devicePort && !validPort(devicePort, 1) ? t("devices.ports.devicePortRange") : "";
  const validMapping = !publicError && !deviceError && Boolean(selectedDeviceId) && validPort(publicPort, 1024) && validPort(devicePort, 1);
  const targetFor = (targetDeviceId: string) => {
    for (const member of snapshot.members) {
      const device = member.devices.find((candidate) => candidate.id === targetDeviceId);
      if (device) return { member, device };
    }
    return null;
  };

  return (
    <div className="port-forward-panel ports-card">
      <div className="ports-heading">
        <h2>{t("devices.ports.title")}</h2>
        {available && <span className="count-chip">{t("devices.ports.count", { used: forwards.length, max: MAX_FORWARDS })}</span>}
      </div>

      {!available ? (
        <div className="devices-notice"><Wrench size={19} aria-hidden="true" /> <p>{t("devices.ports.unavailable")}</p></div>
      ) : (
        <>
          {targets.length === 0 ? (
            <div className="devices-notice" role="status">
              <p>{t(accessLevel === "member" ? "devices.ports.noTargetsMember" : "devices.ports.noTargets")}</p>
              {accessLevel !== "member" && onAddDevice && <button className="secondary-button" onClick={onAddDevice}>{t("devices.ports.manageDevices")}</button>}
            </div>
          ) : (
            <>
              {/* The one warning, shown only to someone who can open a port. */}
              <p className="ports-warning"><Warning size={18} weight="fill" aria-hidden="true" /> <span>{t("devices.ports.exposure")}</span></p>
              <form className="ports-form" onSubmit={(event) => void onCreate(event)}>
                <div className="ports-form-fields">
                  <Field label={t("devices.ports.protocol")}>
                    <select value={protocol} onChange={(event) => onProtocolChange(event.target.value as PortForwardProtocol)} disabled={busy !== null}>
                      <option value="tcp">{protocolName("tcp")}</option>
                      <option value="udp">{protocolName("udp")}</option>
                    </select>
                  </Field>
                  <Field label={t("devices.ports.publicPort")} hint={t("devices.ports.publicPortHint")} error={publicError || undefined}>
                    <input type="number" min="1024" max="65535" inputMode="numeric" value={publicPort}
                      onChange={(event) => onPublicPortChange(event.target.value)} disabled={busy !== null} required />
                  </Field>
                  <Field label={t("devices.ports.device")}>
                    <select value={selectedDeviceId} onChange={(event) => onDeviceChange(event.target.value)} disabled={busy !== null} required>
                      {targets.map(({ member, device }) => (
                        <option value={device.id} key={device.id}>
                          {t("devices.ports.targetOption", { member: member.name, device: device.name, address: device.client_tunnel_address })}
                        </option>
                      ))}
                    </select>
                  </Field>
                  <Field label={t("devices.ports.devicePort")} hint={t("devices.ports.devicePortHint")} error={deviceError || undefined}>
                    <input type="number" min="1" max="65535" inputMode="numeric" value={devicePort}
                      onChange={(event) => onDevicePortChange(event.target.value)} disabled={busy !== null} required />
                  </Field>
                </div>
                <div className="ports-form-footer">
                  <p className="ports-preview" aria-label={t("devices.ports.previewLabel")}>
                    {validMapping ? (
                      <Rich
                        id="devices.ports.preview"
                        params={{
                          protocol: protocolName(protocol),
                          publicPort: Number(publicPort),
                          device: targetFor(selectedDeviceId)?.device.name ?? "",
                          devicePort: Number(devicePort),
                        }}
                        tags={{ strong: (content) => <strong>{content}</strong> }}
                      />
                    ) : full ? t("devices.ports.full", { max: MAX_FORWARDS }) : !publicPort || !devicePort ? t("devices.ports.previewEmpty") : t("devices.ports.previewInvalid")}
                  </p>
                  <button className="primary-button" type="submit" disabled={busy !== null || !validMapping || full}>
                    {busy === "create" ? <ArrowClockwise className="spin" size={16} /> : <Plus size={16} weight="bold" />}
                    {busy === "create" ? t("devices.ports.opening") : t("devices.ports.open")}
                  </button>
                </div>
              </form>
            </>
          )}

          <ul className="ports-list" aria-label={t("devices.ports.listLabel")}>
            {forwards.length === 0 ? (
              <li className="ports-empty">{t("devices.ports.empty")}</li>
            ) : (
              forwards.map((forward) => {
                const target = targetFor(forward.device_id);
                const removable = Boolean(target && canManagePortForwards(accessLevel, target.member));
                const key = `${forward.protocol}:${forward.public_port}`;
                return (
                  <li className="ports-rule" key={key}>
                    <span className={`ports-protocol ${forward.protocol}`}>{protocolName(forward.protocol)}</span>
                    <span className="ports-rule-copy">
                      <span className="ports-route mono">
                        {forward.public_port}
                        <ArrowRight size={14} aria-hidden="true" />
                        {target?.device.client_tunnel_address ?? t("common.state.unavailable")}:{forward.device_port}
                      </span>
                      <small>
                        {target
                          ? t(target.member.suspended ? "devices.ports.targetPaused" : "devices.ports.target", { member: target.member.name, device: target.device.name })
                          : t("devices.ports.targetUnavailable")}
                      </small>
                    </span>
                    {removable ? (
                      <button
                        className="text-button danger-text"
                        aria-label={t("devices.ports.closeLabel", { protocol: protocolName(forward.protocol), publicPort: forward.public_port, device: target?.device.name ?? forward.device_id, devicePort: forward.device_port })}
                        disabled={busy !== null}
                        onClick={() => void onRemove(forward.protocol, forward.public_port)}
                      >
                        {busy === key ? <Busy label={t("devices.ports.closing")} /> : t("devices.ports.close")}
                      </button>
                    ) : (
                      <span className="ports-managed">{t("devices.ports.ownerManaged")}</span>
                    )}
                  </li>
                );
              })
            )}
          </ul>
          {(targets.length > 0 || forwards.length > 0) && (
            <p className="settings-note">
              <Rich id="devices.ports.visitorAddress" params={{ address: GATEWAY_ADDRESS }} tags={{ address: (content) => <span className="mono">{content}</span> }} />
            </p>
          )}
        </>
      )}
    </div>
  );
}
