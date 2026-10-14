import { CaretRight, Plus, Warning, Wrench } from "@phosphor-icons/react";
import { type FormEvent } from "react";
import { canManagePortForwards } from "../../access";
import { type MembershipSnapshot, type PortForwardProtocol } from "../../types";
import { t } from "../../i18n";
import { Rich } from "../../i18n/Rich";

const MAX_FORWARDS = 32;
const GATEWAY_ADDRESS = "10.77.0.1";
/** Protocol names are the same in every language. */
const protocolName = (protocol: PortForwardProtocol) => protocol.toUpperCase();

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
  onRemove: (
    protocol: PortForwardProtocol,
    publicPort: number,
  ) => Promise<void>;
}) {
  const targets = snapshot.members.flatMap((member) =>
    !member.suspended && canManagePortForwards(accessLevel, member)
      ? member.devices.map((device) => ({ member, device }))
      : [],
  );
  const selectedDeviceId = targets.some(({ device }) => device.id === deviceId)
    ? deviceId
    : targets[0]?.device.id || "";
  const forwards = snapshot.port_forwards ?? [];
  const validPort = (value: string, minimum: number) =>
    value.trim() !== "" &&
    Number.isInteger(Number(value)) &&
    Number(value) >= minimum &&
    Number(value) <= 65535;
  const publicError = serverError || (publicPort && !validPort(publicPort, 1024) ? Number(publicPort) < 1024 ? t("devices.ports.publicPortLow") : t("devices.ports.publicPortRange") : "");
  const deviceError = devicePort && !validPort(devicePort, 1) ? t("devices.ports.devicePortRange") : "";
  const validMapping =
    !publicError && !deviceError &&
    Boolean(selectedDeviceId) &&
    validPort(publicPort, 1024) &&
    validPort(devicePort, 1);
  const targetFor = (targetDeviceId: string) => {
    for (const member of snapshot.members) {
      const device = member.devices.find(
        (candidate) => candidate.id === targetDeviceId,
      );
      if (device) return { member, device };
    }
    return null;
  };

  return (
    <div className="port-forward-panel">
      <div className="port-forward-heading">
        <div>
          <h2>{t("devices.ports.title")}</h2>
        </div>
        <span className="port-forward-count">
          {t("devices.ports.count", { used: forwards.length, max: MAX_FORWARDS })}
        </span>
      </div>

      {!available ? (
        <div className="access-empty">
          <Wrench size={19} /> {t("devices.ports.unavailable")}
        </div>
      ) : (
        <>
          <div className="port-forward-notice">
            <Warning size={20} />
            <p>
              <strong>{t("devices.ports.exposure")}</strong>
            </p>
          </div>
          {targets.length === 0 ? <div className="access-empty" role="status"><p>{t(accessLevel === "member" ? "devices.ports.noTargetsMember" : "devices.ports.noTargets")}</p>{accessLevel !== "member" && onAddDevice && <button className="secondary-button" onClick={onAddDevice}>{t("devices.ports.manageDevices")}</button>}</div> : <form
            className="port-forward-form"
            onSubmit={(event) => void onCreate(event)}
          >
            <label>
              <span>{t("devices.ports.protocol")}</span>
              <select
                value={protocol}
                onChange={(event) =>
                  onProtocolChange(event.target.value as PortForwardProtocol)
                }
                disabled={busy !== null}
              >
                <option value="tcp">{protocolName("tcp")}</option>
                <option value="udp">{protocolName("udp")}</option>
              </select>
            </label>
            <label>
              <span>{t("devices.ports.publicPort")}</span>
              <input
                type="number"
                min="1024"
                max="65535"
                inputMode="numeric"
                placeholder="48080"
                aria-invalid={Boolean(publicError)} aria-describedby={publicError ? "forward-public-error" : undefined}
                value={publicPort}
                onChange={(event) => onPublicPortChange(event.target.value)}
                disabled={busy !== null}
                required
              />
            </label>
            <label className="port-forward-device-field">
              <span>{t("devices.ports.device")}</span>
              <select
                value={selectedDeviceId}
                onChange={(event) => onDeviceChange(event.target.value)}
                disabled={busy !== null || targets.length === 0}
                required
              >
                {targets.length === 0 ? (
                  <option value="">{t("devices.ports.noDevice")}</option>
                ) : null}
                {targets.map(({ member, device }) => (
                  <option value={device.id} key={device.id}>
                    {t("devices.ports.targetOption", { member: member.name, device: device.name, address: device.client_tunnel_address })}
                  </option>
                ))}
              </select>
            </label>
            <label>
              <span>{t("devices.ports.devicePort")}</span>
              <input
                type="number"
                min="1"
                max="65535"
                inputMode="numeric"
                placeholder="8080"
                aria-invalid={Boolean(deviceError)} aria-describedby={deviceError ? "forward-device-error" : undefined}
                value={devicePort}
                onChange={(event) => onDevicePortChange(event.target.value)}
                disabled={busy !== null}
                required
              />
            </label>
            {publicError && <p id="forward-public-error" className="field-error" role="alert">{publicError}</p>}
            {deviceError && <p id="forward-device-error" className="field-error" role="alert">{deviceError}</p>}
            <p className="forward-preview" aria-label={t("devices.ports.previewLabel")}>
              {validMapping ? (
                <Rich
                  id="devices.ports.preview"
                  params={{
                    protocol: protocolName(protocol),
                    publicPort: Number(publicPort),
                    device: targetFor(selectedDeviceId)?.device.name ?? t("devices.ports.chooseDevice"),
                    devicePort: Number(devicePort),
                  }}
                  tags={{ strong: (content) => <strong>{content}</strong> }}
                />
              ) : !publicPort || !devicePort ? (
                t("devices.ports.previewEmpty")
              ) : (
                t("devices.ports.previewInvalid")
              )}
            </p>
            <button
              className="secondary-button port-forward-submit"
              type="submit"
              disabled={busy !== null || !validMapping || forwards.length >= MAX_FORWARDS}
            >
              <Plus size={15} weight="bold" />{" "}
              {busy === "create" ? t("devices.ports.opening") : t("devices.ports.open")}
            </button>
          </form>}

          <div className="port-forward-notice">
            <Warning size={17} weight="fill" />
            <p>
              <Rich
                id="devices.ports.visitorAddress"
                params={{ address: GATEWAY_ADDRESS }}
                tags={{ address: (content) => <span className="mono">{content}</span> }}
              />
            </p>
          </div>

          <div className="port-forward-list">
            {forwards.length === 0 ? (
              <p className="port-forward-empty">{t("devices.ports.empty")}</p>
            ) : (
              forwards.map((forward) => {
                const target = targetFor(forward.device_id);
                const removable = Boolean(
                  target && canManagePortForwards(accessLevel, target.member),
                );
                const key = `${forward.protocol}:${forward.public_port}`;
                return (
                  <div className="port-forward-row" key={key}>
                    <span
                      className={`port-forward-protocol ${forward.protocol}`}
                    >
                      {protocolName(forward.protocol)}
                    </span>
                    <span className="port-forward-route mono">
                      :{forward.public_port}
                      <CaretRight size={14} />
                      {target?.device.client_tunnel_address ?? t("common.state.unavailable")}:
                      {forward.device_port}
                    </span>
                    <span className="port-forward-target">
                      {target
                        ? t(target.member.suspended ? "devices.ports.targetPaused" : "devices.ports.target", { member: target.member.name, device: target.device.name })
                        : t("devices.ports.targetUnavailable")}
                    </span>
                    {removable ? (
                      <button
                        className="text-button danger-text"
                        aria-label={t("devices.ports.closeLabel", { protocol: protocolName(forward.protocol), publicPort: forward.public_port, device: target?.device.name ?? forward.device_id, devicePort: forward.device_port })}
                        disabled={busy !== null}
                        onClick={() =>
                          void onRemove(forward.protocol, forward.public_port)
                        }
                      >
                        {busy === key ? t("devices.ports.closing") : t("devices.ports.close")}
                      </button>
                    ) : (
                      <span className="port-forward-managed">
                        {t("devices.ports.ownerManaged")}
                      </span>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </>
      )}
    </div>
  );
}
