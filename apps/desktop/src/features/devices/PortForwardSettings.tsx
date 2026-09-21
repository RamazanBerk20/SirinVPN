import { InlineError } from "../../components/ui";
import { useAccessController, type AccessProps } from "./useAccessController";
import { PortForwardPanel } from "./PortForwardPanel";
export function PortForwardSettings(props: AccessProps & { onManageDevices?: () => void }) {
  const m = useAccessController(props);
  return (
    <section className="settings-card" aria-label="Port forwarding">
      {!props.connected ? (
        <>
          <h2>Port forwarding · VPS</h2>
          <p>Connect to view or change public ports on {props.profile.name}.</p>
        </>
      ) : !m.snapshot ? (
        <>
          <h2>Port forwarding · VPS</h2>
          <p>
            {m.loading
              ? "Reading server configuration…"
              : "Server configuration is unavailable."}
          </p>
        </>
      ) : (
        <PortForwardPanel
          onAddDevice={props.onManageDevices}
          serverError={m.error && /reserved|public.*port/i.test(m.error) ? m.error : undefined}
          snapshot={m.snapshot}
          accessLevel={props.accessLevel}
          available={m.portForwardingAvailable === true && !m.loadError}
          protocol={m.forwardProtocol}
          publicPort={m.forwardPublicPort}
          deviceId={m.forwardDeviceId}
          devicePort={m.forwardDevicePort}
          busy={m.forwardBusy}
          onProtocolChange={m.setForwardProtocol}
          onPublicPortChange={m.setForwardPublicPort}
          onDeviceChange={m.setForwardDeviceId}
          onDevicePortChange={m.setForwardDevicePort}
          onCreate={m.createPortForward}
          onRemove={m.removePortForward}
        />
      )}
      {(m.loadError || m.error) && (
        <InlineError message={m.loadError || m.error!} />
      )}
    </section>
  );
}
