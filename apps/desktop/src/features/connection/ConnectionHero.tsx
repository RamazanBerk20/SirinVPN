import { ArrowClockwise, GearSix, Info, Power, Warning, WarningOctagon } from "@phosphor-icons/react";
import { useEffect, useRef, useState, type ReactNode } from "react";
import { api } from "../../api";
import { dpadOnly, invoke, isAndroid } from "../../platform";
import type { Page } from "../../components/Navigation";
import { formatTransport, formatLatency } from "../../format";
import { describeConnection } from "./connectionState";
import { protectionEvidence } from "./protectionEvidence";
import { InfoHint } from "../../components/InfoHint";
import { formatNumber, t } from "../../i18n";
import type { LocalTunnelStatus, ServerProfile } from "../../types";
import type { ServerWorkspaceModel } from "./useServerWorkspace";
import { backupAge, needsAttention, useVpsBackupSchedule } from "../settings/vpsBackupSchedules";

type Alert = { id: string; tone: "danger" | "warn" | "info"; message: string; action?: { label: string; run: () => void } };

/** The running method, with "Automatic" in front when the app chose it. */
export function methodLabel(local: LocalTunnelStatus, profile: ServerProfile, saved: string | undefined) {
  const method = local.transport === "tls_like" && profile.tls_like?.https ? t("home.method.https") : formatTransport(local.transport);
  return saved === "automatic" ? t("home.method.automatic", { method }) : method;
}

/** Share of reachability probes that got no reply, when enough were sent to mean something. */
function probeLoss(local: LocalTunnelStatus) {
  const sample = local.transport_quality?.sample;
  return sample && sample.probes_sent >= 4 ? 1 - sample.probes_received / sample.probes_sent : 0;
}

export function ConnectionHero({
  model,
  view,
  onReviewComponentUpdate,
  onShowActive,
  onOpenMaintenance,
}: {
  model: ServerWorkspaceModel;
  view: Page;
  onReviewComponentUpdate?: () => void;
  /** Selects the server whose tunnel is up, when it is not this one. */
  onShowActive?: () => void;
  onOpenMaintenance?: () => void;
}) {
  const power = useRef<HTMLButtonElement>(null);
  // D-pad only: Home starts on this button, and it takes focus back after being disabled while busy.
  useEffect(() => { if (dpadOnly && document.activeElement === document.body) power.current?.focus(); });
  const backupSchedule = useVpsBackupSchedule(model.profile.id);
  // The local component reports its own update need; status flags only cover two of its features.
  const [componentCheck, setComponentCheck] = useState(false);
  useEffect(() => {
    if (isAndroid) return;
    let current = true;
    Promise.resolve().then(() => api.localComponentUpdateStatus()).then((status) => { if (current) setComponentCheck(status?.update_required === true); }).catch(() => undefined);
    return () => { current = false; };
  }, [model.localStatus.state]);
  if (view !== "home") return null;
  const { localStatus, profile, serverStatus, busy, error, connectionOperation: operation } = model;
  const systemControlled = isAndroid && localStatus.always_on === true;
  const state = describeConnection(localStatus, profile.id, serverStatus, model.preferences.saved?.policy);
  const loading = !state.known && model.freshness.updatedAt === null && model.freshness.refreshing;
  const waiting = state.active && localStatus.waiting_for_user === true;
  const autoReconnecting = state.statusState === "reconnecting" && !busy;
  const componentUpdateRequired = !isAndroid && state.known && (
    componentCheck ||
    localStatus.mtu_detection_supported === false ||
    localStatus.endpoint_updates_supported === false
  );
  // Lost reachability checks undermine the connection as much as a fault the status reports.
  const unstable = state.connected && probeLoss(localStatus) >= 0.2;
  const tone = busy || loading || autoReconnecting ? "busy" : unstable && state.tone === "ok" ? "warn" : state.tone;
  const headline = loading ? t("home.status.checking")
    : operation === "connecting" ? t("home.status.connectingTo", { name: profile.name })
    : operation === "disconnecting" ? t("home.status.disconnecting")
    : busy ? t("home.status.changing")
    : state.status;
  const summary = loading ? "" : operation === "connecting" ? t("home.summary.connecting")
    : operation === "disconnecting" ? t("home.summary.disconnecting") : state.summary;

  const ring: { icon: ReactNode; label: string; aria?: string; run?: () => void; disabled?: boolean } = systemControlled
    ? { icon: <GearSix size={36} />, label: t("home.action.vpnSettings"), aria: t("home.action.androidVpnSettings"), run: () => void invoke("android_vpn_settings") }
    : loading ? { icon: <ArrowClockwise size={36} className="spin" />, label: t("common.state.checking"), aria: t("home.status.checking"), disabled: true }
    : busy || autoReconnecting ? { icon: <ArrowClockwise size={36} className="spin" />, label: operation === "disconnecting" ? t("home.action.disconnecting") : operation === "connecting" ? t("home.action.connecting") : autoReconnecting ? t("home.status.reconnecting") : t("home.action.wait"), aria: t("home.action.changing"), disabled: true }
    : !state.known ? { icon: <ArrowClockwise size={36} />, label: t("home.action.refresh"), run: () => void model.onRefresh() }
    : waiting ? { icon: <ArrowClockwise size={36} />, label: t("home.action.reconnect"), run: () => void model.resume() }
    : componentUpdateRequired && !state.active && onReviewComponentUpdate ? { icon: <Power size={36} />, label: state.action, run: onReviewComponentUpdate }
    : { icon: <Power size={36} />, label: state.active ? t("home.action.disconnect") : state.action, aria: state.action, run: () => void model.toggle(), disabled: state.other };

  const alerts: Alert[] = [];
  const diagnose = { label: t("home.alert.runDiagnostics"), run: () => void model.runDiagnostics() };
  if (error) alerts.push({ id: "error", tone: "danger", message: error, action: state.connected
    ? { label: t("home.action.refresh"), run: () => void model.onRefresh() }
    : { label: t("help.troubleshoot.open"), run: () => model.setTroubleshootOpen(true) } });
  if (state.warningState) {
    const info = state.warningState === "androidLockdown" || state.warningState === "accessContained";
    const repair = state.warningState === "serverInterfaceDown" && onOpenMaintenance ? { label: t("home.alert.checkServer"), run: onOpenMaintenance } : undefined;
    alerts.push({ id: "warning", tone: info ? "info" : "warn", message: state.warning ?? "",
      action: info || state.warningState === "accessUnenforced" ? undefined : repair ?? diagnose });
  }
  if (unstable) {
    const sample = localStatus.transport_quality!.sample!;
    alerts.push({ id: "loss", tone: "warn", message: t("home.alert.unstable", { lost: sample.probes_sent - sample.probes_received, sent: sample.probes_sent }), action: diagnose });
  }
  const storage = serverStatus?.disk_total_bytes ? (serverStatus.disk_used_bytes ?? 0) / serverStatus.disk_total_bytes : 0;
  if (state.connected && storage >= 0.9) alerts.push({ id: "storage", tone: "warn", message: t("home.alert.storage", { percent: formatNumber(storage, { style: "percent", maximumFractionDigits: 0 }) }), action: onOpenMaintenance && { label: t("home.alert.checkServer"), run: onOpenMaintenance } });
  if (model.rotationPendingConfirmed) alerts.push({ id: "rotation", tone: "warn", message: t("home.alert.rotationPending"), action: { label: t("home.alert.finishRotation"), run: () => model.setRotationOpen(true) } });
  if (componentUpdateRequired && onReviewComponentUpdate) alerts.push({ id: "component", tone: "warn", message: t("home.componentUpdate.needed"), action: { label: t("home.componentUpdate.review"), run: onReviewComponentUpdate } });
  if (model.presharedKeyMissing) alerts.push({ id: "psk", tone: "info", message: t("home.presharedKey.missing"), action: { label: t("home.presharedKey.add"), run: () => model.setRotationOpen(true) } });
  if (profile.role === "owner" && needsAttention(backupSchedule)) alerts.push({ id: "backup", tone: "info",
    message: backupSchedule?.last_failure ? t("vps.schedule.notice.failed") : backupSchedule?.last_success ? t("vps.schedule.notice.stale", { age: backupAge(backupSchedule.last_success) }) : t("vps.schedule.notice.none"),
    action: { label: t("vps.schedule.notice.review"), run: () => model.setVpsBackupScheduleOpen(true) } });

  const troubleshoot = !error && !state.connected && localStatus.server_id === profile.id && localStatus.state === "degraded";
  return (
    <section className="connection-console" data-tone={tone} aria-label={t("home.consoleLabel")}>
      <div className="hero-panel">
        <button
          className="power-control"
          ref={power}
          disabled={ring.disabled}
          aria-label={ring.aria ?? ring.label}
          onClick={ring.run}
        >
          {ring.icon}
          <span>{ring.label}</span>
        </button>
        <div className="hero-copy">
          <p className="connection-state" role="status">{headline}</p>
          {summary && <p className="connection-explanation">{summary}</p>}
          {systemControlled && <p className="connection-note">{t("home.alwaysOnNote")}</p>}
          {!isAndroid && state.connected && localStatus.kill_switch_enabled && <p className="connection-note">{t("home.consequence.desktop")}</p>}
          <ConnectionFacts model={model} />
          <div className="hero-actions">
            {operation === "connecting" && <button className="secondary-button" type="button" onClick={() => void model.cancelConnection()}>{t("home.action.cancelConnection")}</button>}
            {!systemControlled && !loading && !state.known && !operation && <button className="secondary-button" type="button" onClick={() => void model.cancelConnection()}>{t("home.action.stop")}</button>}
            {!systemControlled && (waiting || autoReconnecting) && <button className="secondary-button" type="button" disabled={busy} onClick={() => void model.toggle()}>{state.action}</button>}
            {state.statusState === "monitorUnavailable" && <button className="secondary-button" type="button" disabled={busy} onClick={() => void model.onRefresh()}>{t("home.action.checkAgain")}</button>}
            {state.other && onShowActive && <button className="secondary-button" type="button" onClick={onShowActive}>{t("home.action.showActive")}</button>}
            {troubleshoot && <button className="text-button" type="button" disabled={busy} onClick={() => model.setTroubleshootOpen(true)}>{t("help.troubleshoot.open")}</button>}
          </div>
        </div>
      </div>
      {alerts.length > 0 && <ul className="home-alerts" aria-label={t("home.alert.label")}>
        {alerts.map((alert) => <li key={alert.id} className={`home-alert ${alert.tone}`} role={alert.tone === "info" ? undefined : "alert"}>
          {alert.tone === "danger" ? <WarningOctagon size={20} weight="fill" /> : alert.tone === "warn" ? <Warning size={20} weight="fill" /> : <Info size={20} weight="fill" />}
          <p>{alert.message}</p>
          {alert.action && <button className="secondary-button" type="button" disabled={busy} onClick={alert.action.run}>{alert.action.label}</button>}
        </li>)}
      </ul>}
    </section>
  );
}

/** The facts a user checks before trusting the tunnel, as one row of labelled chips. */
export function ConnectionFacts({ model }: { model: ServerWorkspaceModel }) {
  const { localStatus: local, profile, serverStatus } = model;
  const state = describeConnection(local, profile.id, serverStatus, model.preferences.saved?.policy);
  const evidence = protectionEvidence(local);
  const facts: { id: string; label: string; value: string; info?: string; flag?: boolean }[] = [];
  if (state.active) {
    facts.push({ id: "method", label: t("home.details.method"), value: methodLabel(local, profile, model.preferences.saved?.transport) });
    // Android's hero stays short: full tunnel is the default there, so only a narrower scope earns a chip.
    if (!isAndroid || state.routing !== t("home.routing.fullTunnel")) facts.push({ id: "routing", label: t("home.details.routing"), value: state.routing });
  }
  if (isAndroid) {
    if (local.lockdown) facts.push({ id: "lockdown", label: t("home.details.blockWithoutVpn"), value: t("common.state.enabled") });
  } else if (state.known && !state.other) {
    // While connected, "Blocking traffic" means only that non-VPN traffic is blocked, which is what "On" promises.
    const value = state.connected && state.protectionState === "blocking" ? t("home.killSwitch.armed") : state.protection;
    facts.push({ id: "killSwitch", label: t("home.details.killSwitch"), value, flag: ["failed", "unknown", "unverified"].includes(state.protectionState) });
  }
  if (state.connected && local.routing_mode !== "selected_routes" && (isAndroid || local.routing_mode !== "selected_applications")) {
    facts.push({ id: "ipv6", label: t("home.device.ipv6"), value: evidence.ipv6, flag: !local.ipv6_tunneled && !(local.ipv6_blocked && (evidence.verified || isAndroid)) });
  }
  if (state.applicationIsolation) facts.push({ id: "isolation", label: t("home.details.appIsolation"), value: state.applicationIsolation });
  if (state.connected && !isAndroid) {
    const reach = state.health.reachabilityState;
    const latency = serverStatus?.management_latency_ms;
    const value = reach === "notChecked" ? latency === undefined ? null : formatLatency(latency)
      : latency === undefined || reach === "noReply" ? state.health.reachability
      : t("common.separator.pair", { first: state.health.reachability, second: formatLatency(latency) });
    if (value) facts.push({ id: "server", label: t("home.details.server"), value, info: t("home.details.serverResponseInfo"), flag: reach === "noReply" });
  }
  if (facts.length === 0) return null;
  return <dl className="connection-facts">
    {facts.map((fact) => <div key={fact.id} className={fact.flag ? "flagged" : undefined}>
      <dt>{fact.label}{fact.info && !isAndroid && <InfoHint text={fact.info} />}</dt>
      <dd>{fact.value}</dd>
    </div>)}
  </dl>;
}
