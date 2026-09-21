import { CaretRight, Plus, Warning, Wrench } from "@phosphor-icons/react";
import { type FormEvent } from "react";
import { canManageMember } from "../../access";
import { type MembershipSnapshot, type PortForwardProtocol } from "../../types";

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
    !member.suspended && (canManageMember(accessLevel, member) || (accessLevel === "member" && member.policy?.manage_own_port_forwards))
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
  const publicError = serverError || (publicPort && !validPort(publicPort, 1024) ? Number(publicPort) < 1024 ? "Public port must be 1024–65535. Low ports are reserved." : "Public port must be 1024–65535." : "");
  const deviceError = devicePort && !validPort(devicePort, 1) ? "Device port must be 1–65535." : "";
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
          <h2>Port forwarding · VPS</h2>
          <p>
            Open one explicit IPv4 TCP or UDP port and send it to one authorized
            VPN device.
          </p>
        </div>
        <span className="port-forward-count">
          {forwards.length} / 32 configured
        </span>
      </div>

      {!available ? (
        <div className="access-empty">
          <Wrench size={19} /> Repair this VPS with the current app build to
          enable port forwarding.
        </div>
      ) : (
        <>
          <div className="port-forward-notice">
            <Warning size={20} />
            <p>
              <strong>
                This exposes the selected device service to the public internet.
              </strong>
            </p>
          </div>
          {targets.length === 0 ? <div className="access-empty" role="status"><p>{accessLevel === "member" ? "Your current membership has no eligible device or permission for port forwarding. Ask an Owner or Admin to review your access." : "Authorize an active device before opening a port."}</p>{accessLevel !== "member" && onAddDevice && <button className="secondary-button" onClick={onAddDevice}>Manage devices and invitations</button>}</div> : <form
            className="port-forward-form"
            onSubmit={(event) => void onCreate(event)}
          >
            <label>
              <span>Protocol</span>
              <select
                value={protocol}
                onChange={(event) =>
                  onProtocolChange(event.target.value as PortForwardProtocol)
                }
                disabled={busy !== null}
              >
                <option value="tcp">TCP</option>
                <option value="udp">UDP</option>
              </select>
            </label>
            <label>
              <span>Public port</span>
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
              <span>Target device</span>
              <select
                value={selectedDeviceId}
                onChange={(event) => onDeviceChange(event.target.value)}
                disabled={busy !== null || targets.length === 0}
                required
              >
                {targets.length === 0 ? (
                  <option value="">No manageable device</option>
                ) : null}
                {targets.map(({ member, device }) => (
                  <option value={device.id} key={device.id}>
                    {member.name} / {device.name} ·{" "}
                    {device.client_tunnel_address}
                  </option>
                ))}
              </select>
            </label>
            <label>
              <span>Device port</span>
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
            <p className="forward-preview" aria-label="Mapping preview">
              {validMapping ? (
                <>
                  Public {protocol.toUpperCase()} port{" "}
                  <strong>{Number(publicPort)}</strong> →{" "}
                  <strong>
                    {targetFor(selectedDeviceId)?.device.name ??
                      "Choose a device"}
                  </strong>{" "}
                  → port <strong>{Number(devicePort)}</strong>
                </>
              ) : !publicPort || !devicePort ? (
                "Enter both ports to preview the forwarding rule."
              ) : (
                "Correct the highlighted fields to preview this rule."
              )}
            </p>
            <button
              className="secondary-button port-forward-submit"
              type="submit"
              disabled={busy !== null || !validMapping || forwards.length >= 32}
            >
              <Plus size={15} weight="bold" />{" "}
              {busy === "create" ? "Opening" : "Open port"}
            </button>
          </form>}

          <div className="port-forward-notice">
            <Warning size={17} weight="fill" />
            <p>
              The service sees the VPN gateway address{" "}
              <span className="mono">10.77.0.1</span>, not the visitor&apos;s
              original IP. Low and SirinVPN control ports stay reserved.
            </p>
          </div>

          <div className="port-forward-list">
            {forwards.length === 0 ? (
              <p className="port-forward-empty">No public ports are open.</p>
            ) : (
              forwards.map((forward) => {
                const target = targetFor(forward.device_id);
                const removable = Boolean(
                  target && canManageMember(accessLevel, target.member),
                );
                const key = `${forward.protocol}:${forward.public_port}`;
                return (
                  <div className="port-forward-row" key={key}>
                    <span
                      className={`port-forward-protocol ${forward.protocol}`}
                    >
                      {forward.protocol.toUpperCase()}
                    </span>
                    <span className="port-forward-route mono">
                      :{forward.public_port}
                      <CaretRight size={14} />
                      {target?.device.client_tunnel_address ?? "Unavailable"}:
                      {forward.device_port}
                    </span>
                    <span className="port-forward-target">
                      {target
                        ? `${target.member.name} / ${target.device.name}`
                        : "Target unavailable"}
                      {target?.member.suspended &&
                        " · Paused while member is suspended"}
                    </span>
                    {removable ? (
                      <button
                        className="text-button danger-text"
                        aria-label={`Close port ${forward.protocol.toUpperCase()} ${forward.public_port} to ${target?.device.name ?? forward.device_id}:${forward.device_port}`}
                        disabled={busy !== null}
                        onClick={() =>
                          void onRemove(forward.protocol, forward.public_port)
                        }
                      >
                        {busy === key ? "Closing" : "Close port"}
                      </button>
                    ) : (
                      <span className="port-forward-managed">
                        Owner managed
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
