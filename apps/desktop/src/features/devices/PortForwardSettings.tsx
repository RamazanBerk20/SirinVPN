import { InlineError } from "../../components/ui";
import { useAccessController, type AccessProps } from "./useAccessController";
import { PortForwardPanel } from "./PortForwardPanel";
import { t } from "../../i18n";
export function PortForwardSettings(props: AccessProps & { onManageDevices?: () => void }) {
  const m = useAccessController(props);
  return (
    <section className="settings-card" aria-label={t("devices.ports.title")}>
      {!props.connected ? (
        <>
          <h2>{t("devices.ports.title")}</h2>
          <p>{t("devices.ports.connectFirst", { server: props.profile.name })}</p>
        </>
      ) : !m.snapshot ? (
        <>
          <h2>{t("devices.ports.title")}</h2>
          <p>
            {m.loading
              ? t("common.state.loading")
              : t("devices.ports.settingsUnavailable")}
          </p>
        </>
      ) : (
        <PortForwardPanel
          onAddDevice={props.onManageDevices}
          serverError={m.publicPortError ?? undefined}
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
