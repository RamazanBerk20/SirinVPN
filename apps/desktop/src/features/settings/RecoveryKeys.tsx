import { isAndroid } from "../../platform";
import { copyText } from "../../lib/clipboard";
import { SecretInput } from "../../components/SecretInput";
import { ShareEncryptedFile } from "../../components/ShareEncryptedFile";
import { confirmAction } from "../../lib/confirmAction";
import { SecretQr } from "../devices/InvitationShare";
import { ConfirmationRow } from "../../components/ConfirmationRow";
import { useSecretNavigationGuard } from "../../hooks/useSecretNavigationGuard";
import { useCallback, useEffect, useRef, useState } from "react";
import { save } from "../../lib/nativeDialog";
import { ArrowClockwise, Copy, DownloadSimple, Key } from "@phosphor-icons/react";
import { api } from "../../api";
import { Field, InlineError } from "../../components/ui";
import { notify } from "../../components/Toasts";
import { errorMessage } from "../../lib/errors";
import type { MemberSummary, RecoveryKeyOutput, RecoverySettings, ServerProfile } from "../../types";
import { formatList, t } from "../../i18n";
import { useInfoHint } from "../../components/InfoHint";
import { ConnectFirst, SettingsDisclosure, SettingsNotice } from "./SettingsParts";

/** Where a result appears: next to the control that caused it. */
type Spot = "load" | "create" | "copy" | "export" | "admins";
const FINISHING_REFRESH_MS = 10_000;

export function RecoveryKeys({ profile, connected, owner, onConnect, onUpdate }: {
  profile: Pick<ServerProfile, "id">;
  connected: boolean;
  owner: boolean;
  /** Connects to this server in place; without it the card only says to connect. */
  onConnect?: () => void;
  /** Opens the VPS update for a server too old for recovery keys. */
  onUpdate?: () => void;
}) {
  const [settings, setSettings] = useState<RecoverySettings | null>(null);
  const [admins, setAdmins] = useState<MemberSummary[]>([]), [selected, setSelected] = useState<string[]>([]);
  const [supported, setSupported] = useState<boolean | null>(null);
  const [created, setCreated] = useState<RecoveryKeyOutput | null>(null);
  const [accepted, setAccepted] = useState(false), [password, setPassword] = useState(""), [repeat, setRepeat] = useState("");
  const scope = useRef<HTMLElement>(null);
  const generation = useRef(0);
  const inFlight = useRef(false);
  const reading = useRef(0);
  const [retained, setRetained] = useState(false);
  const [exportedPath, setExportedPath] = useState("");
  const clearMaterial = useCallback(() => { setCreated(null); setPassword(""); setRepeat(""); setRetained(false); setExportedPath(""); }, []);
  const [busyAt, setBusyAt] = useState<Spot | null>(null);
  const [feedback, setFeedback] = useState<{ at: Spot; message: string; error?: boolean } | null>(null);
  const busy = busyAt !== null;
  useSecretNavigationGuard(Boolean(created) && !retained || busy, scope, clearMaterial, busy);
  const [info, infoPanel] = useInfoHint(t("settings.recovery.info"), t("settings.recovery.infoLabel"));
  const refresh = useCallback(async (request = generation.current) => {
    const read = ++reading.current;
    const current = () => request === generation.current && read === reading.current;
    if (!connected) { setSettings(null); setSupported(null); return; }
    try {
      const configuration = await api.serverConfiguration(profile.id);
      if (!current()) return;
      setSupported(Boolean(configuration.recovery_keys_enabled));
      if (!configuration.recovery_keys_enabled) return;
      const [next, membership] = await Promise.all([api.recoverySettings(profile.id), api.membership(profile.id)]);
      if (!current()) return;
      setSettings(next); setSelected(next.policy.administrator_member_ids);
      setCreated((current) => current && current.recovery_id === next.key?.recovery_id ? current : null);
      setAdmins(membership.members.filter((member) => member.role === "member" && member.administrator));
      setFeedback((current) => current?.at === "load" ? null : current);
    } catch (reason) { if (current()) setFeedback({ at: "load", message: errorMessage(reason, t("settings.recovery.loadFailed")), error: true }); }
  }, [profile.id, connected]);
  useEffect(() => {
    generation.current += 1;
    inFlight.current = false; setBusyAt(null); setFeedback(null);
    setSettings(null); setSupported(null); setAdmins([]); setSelected([]); setAccepted(false);
    clearMaterial();
    return () => { generation.current += 1; };
  }, [profile.id, clearMaterial]);
  useEffect(() => { void refresh(); }, [refresh]);
  // A previous key is still being enrolled: check again on our own instead of asking the user to wait and reload.
  const finishing = Boolean(settings?.enrollment_finishing);
  useEffect(() => {
    if (!finishing || !connected) return;
    const timer = setInterval(() => void refresh(), FINISHING_REFRESH_MS);
    return () => clearInterval(timer);
  }, [finishing, connected, refresh]);
  const action = async (at: Spot, work: (current: () => boolean) => Promise<void>) => {
    if (inFlight.current) return;
    const request = generation.current;
    const current = () => request === generation.current;
    inFlight.current = true;
    setBusyAt(at); setFeedback(null);
    try { await work(current); } catch (reason) { if (current()) setFeedback({ at, message: errorMessage(reason, t("settings.recovery.actionFailed")), error: true }); }
    finally { if (current()) { inFlight.current = false; setBusyAt(null); } }
  };
  const create = () => action("create", async (current) => {
    setRetained(false);
    const material = await api.createRecoveryKey(profile.id, settings?.key?.recovery_id ?? null, accepted);
    if (!current()) return;
    setCreated(material);
    await refresh();
  });
  const exportPackage = () => action("export", async (current) => {
    if (!created) return;
    const path = await save({ purpose: "recovery_export", defaultPath: "sirinvpn-recovery.sirrec", filters: [{ name: t("settings.recovery.key.fileType"), extensions: ["sirrec"] }] });
    if (!path || !current()) return;
    await api.exportRecoveryPackage(created.key, path, password, accepted);
    if (!current()) return;
    setExportedPath(path);
    setPassword(""); setRepeat(""); setFeedback({ at: "export", message: t("settings.recovery.key.saved") });
  });
  const finish = () => {
    // The acknowledgement covered this key only; a later Replace must be acknowledged again.
    clearMaterial(); setAccepted(false);
    setFeedback({ at: "create", message: t("settings.recovery.key.finished") });
  };
  const say = (at: Spot) => feedback?.at === at && (feedback.error
    ? <InlineError message={feedback.message} onRetry={at === "load" ? () => void refresh() : undefined} />
    : <p className="card-result" role="status">{feedback.message}</p>);
  // The one-time key sits under the button that created it; it stays on screen if the connection drops.
  const qrSource = created ? `data:image/svg+xml;charset=utf-8,${encodeURIComponent(created.qr_svg)}` : "";
  const keyPanel = created && <div className="recovery-key-panel">
    <h3>{t("settings.recovery.key.title")}</h3>
    <SettingsNotice tone="warning">{t("settings.recovery.key.warning")}</SettingsNotice>
    {/* Android keeps the key in the native layer: its viewer shows the key and QR outside the WebView. */}
    {isAndroid ? <SecretQr source={qrSource} kind="recovery" code={created.key} />
      : <Field label={t("settings.recovery.key.label")}><textarea rows={Math.min(12, Math.max(3, Math.ceil(created.key.length / 90)))} readOnly value={created.key} className="secret-code-output mono recovery-key-text" /></Field>}
    <div className="recovery-key-action">
      <button className="secondary-button" disabled={busy} onClick={() => void action("copy", async (current) => { await copyText(created.key); if (current()) setFeedback({ at: "copy", message: t("settings.recovery.key.copied") }); })}><Copy size={17} />{t("settings.recovery.key.copy")}</button>
      {say("copy")}
    </div>
    {!isAndroid && <SettingsDisclosure summary={t("settings.recovery.key.qr")}><SecretQr source={qrSource} kind="recovery" code={created.key} /></SettingsDisclosure>}
    <Field label={t("settings.recovery.key.password")} hint={t("settings.recovery.key.passwordHint")}><SecretInput field="password" type="password" autoComplete="new-password" value={password} onChange={(event) => setPassword(event.target.value)} /></Field>
    <Field label={t("settings.recovery.key.repeat")} error={repeat && repeat !== password ? t("common.error.passwordsDiffer") : undefined}><SecretInput field="password" type="password" autoComplete="new-password" value={repeat} onChange={(event) => setRepeat(event.target.value)} /></Field>
    <div className="recovery-key-action">
      <button className="secondary-button" disabled={busy || !accepted || [...password].length < 12 || password !== repeat} onClick={() => void exportPackage()}><DownloadSimple size={17} />{busyAt === "export" ? t("settings.recovery.key.saving") : t("settings.recovery.key.save")}</button>
      {say("export")}
    </div>
    <ShareEncryptedFile uri={exportedPath} />
    <ConfirmationRow checked={retained} onChange={setRetained}>{t("settings.recovery.key.retained")}</ConfirmationRow>
    <button className="primary-button" disabled={!retained || busy} onClick={finish}>{t("settings.recovery.key.finish")}</button>
  </div>;
  const revoke = () => action("create", async (current) => {
    if (!await confirmAction({
      title: t("settings.recovery.revokeConfirm.title"),
      message: t("settings.recovery.revokeConfirm.message"),
      confirm: t("settings.recovery.revokeConfirm.confirm"),
    }) || !current()) return;
    const next = await api.revokeRecoveryKey(profile.id, settings!.key!.recovery_id);
    if (!current()) return;
    setSettings(next); clearMaterial(); setAccepted(false);
    notify(t("settings.recovery.revoked"));
  });
  const saveAdmins = () => action("admins", async (current) => {
    const names = admins.filter(admin => selected.includes(admin.id)).map(admin => t("settings.recovery.admins.entry", { name: admin.name, id: admin.id }));
    const confirmation = names.length ? {
      title: t("settings.recovery.admins.confirm.title"),
      message: t("settings.recovery.admins.confirm.message", { names: formatList(names) }),
      confirm: t("settings.recovery.admins.confirm.confirm"),
    } : {
      title: t("settings.recovery.admins.confirmNone.title"),
      message: t("settings.recovery.admins.confirmNone.message"),
      confirm: t("settings.recovery.admins.confirmNone.confirm"),
    };
    if (!await confirmAction(confirmation) || !current()) return;
    const next = await api.updateRecoveryPolicy(profile.id, selected);
    if (!current()) return;
    setSettings(next); setSelected(next.policy.administrator_member_ids);
    setCreated((current) => current && current.recovery_id === next.key?.recovery_id ? current : null);
    setFeedback({ at: "admins", message: t("settings.recovery.admins.saved") });
  });
  return <section ref={scope} className="settings-card recovery-keys" aria-label={t("settings.recovery.title")}>
    <h2>{t("settings.recovery.title")}</h2>
    <p>{t("settings.recovery.summary")}{info}</p>
    {infoPanel}
    {!connected ? <ConnectFirst onConnect={onConnect} />
      : supported === false ? <SettingsNotice action={onUpdate && { label: t("settings.recovery.update"), onClick: onUpdate }}>{t("settings.recovery.unsupported")}</SettingsNotice>
      : settings ? <>
        {finishing
          ? <p className="busy-line" role="status"><ArrowClockwise className="spin" size={17} />{t("settings.recovery.finishing")}</p>
          : <p className="recovery-state">{settings.key ? t("settings.recovery.registered") : t("settings.recovery.none")}</p>}
        {/* Until the new key's setup is finished, nothing here may replace or revoke it. */}
        {!created && <>
          {!settings.can_issue_key && <p className="settings-note">{t("settings.recovery.cannotIssue")}</p>}
          {settings.can_issue_key && <label className="preference-checkbox"><input type="checkbox" checked={accepted} disabled={finishing || busy} onChange={(event) => setAccepted(event.target.checked)} />
            <span>{t("settings.recovery.accept")}</span>
          </label>}
          {(settings.can_issue_key || settings.key && owner) && <div className="settings-action-row recovery-actions">
            {settings.can_issue_key && <button className="secondary-button" disabled={!accepted || busy || finishing} onClick={() => void create()}><Key size={17} />{busyAt === "create" ? t("settings.recovery.creating") : settings.key ? t("settings.recovery.replace") : t("settings.recovery.create")}</button>}
            {settings.key && owner && <button className="text-button danger-text" disabled={busy} onClick={() => void revoke()}>{t("settings.recovery.revoke")}</button>}
          </div>}
        </>}
        {say("create")}
        {keyPanel}
        {owner && !created && <SettingsDisclosure summary={t("settings.recovery.admins.title")} className="recovery-admins">
          <p>{t("settings.recovery.admins.summary")}</p>
          {admins.length ? admins.map((admin) => <label className="preference-checkbox" key={admin.id}>
            <input type="checkbox" checked={selected.includes(admin.id)} onChange={(event) => setSelected(event.target.checked ? [...selected, admin.id] : selected.filter((id) => id !== admin.id))} />
            <span>{admin.suspended ? t("common.separator.pair", { first: admin.name, second: t("settings.recovery.admins.suspended") }) : admin.name}</span>
          </label>) : <p>{t("settings.recovery.admins.none")}</p>}
          <div className="recovery-key-action">
            <button className="secondary-button" disabled={busy} onClick={() => void saveAdmins()}>{busyAt === "admins" ? t("settings.recovery.admins.saving") : t("settings.recovery.admins.save")}</button>
            {say("admins")}
          </div>
        </SettingsDisclosure>}
      </> : feedback?.at === "load" ? say("load") : <p role="status">{t("common.state.loading")}</p>}
    {!(connected && supported !== false && settings) && keyPanel}
  </section>;
}
