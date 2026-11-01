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
import { Copy, DownloadSimple, Key } from "@phosphor-icons/react";
import { api } from "../../api";
import { Field, InlineError } from "../../components/ui";
import { errorMessage } from "../../lib/errors";
import type { MemberSummary, RecoveryKeyOutput, RecoverySettings, ServerProfile } from "../../types";
import { formatList, t } from "../../i18n";
import { useInfoHint } from "../../components/InfoHint";

export function RecoveryKeys({ profile, connected, owner }: { profile: Pick<ServerProfile, "id">; connected: boolean; owner: boolean }) {
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
  const [exportedPath,setExportedPath] = useState("");
  const clearMaterial = useCallback(() => { setCreated(null); setPassword(""); setRepeat(""); setRetained(false); setExportedPath(""); }, []);
  const [busy, setBusy] = useState(false), [error, setError] = useState<string | null>(null), [notice, setNotice] = useState<string | null>(null);
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
    } catch (reason) { if (current()) setError(errorMessage(reason, t("settings.recovery.loadFailed"))); }
  }, [profile.id, connected]);
  useEffect(() => {
    generation.current += 1;
    inFlight.current = false; setBusy(false); setError(null); setNotice(null);
    setSettings(null); setSupported(null); setAdmins([]); setSelected([]); setAccepted(false);
    clearMaterial();
    return () => { generation.current += 1; };
  }, [profile.id, clearMaterial]);
  useEffect(() => { void refresh(); }, [refresh]);
  const action = async (work: (current: () => boolean) => Promise<void>) => {
    if (inFlight.current) return;
    const request = generation.current;
    const current = () => request === generation.current;
    inFlight.current = true;
    setBusy(true); setError(null); setNotice(null);
    try { await work(current); } catch (reason) { if (current()) setError(errorMessage(reason, t("settings.recovery.actionFailed"))); }
    finally { if (current()) { inFlight.current = false; setBusy(false); } }
  };
  const create = () => action(async (current) => {
    setRetained(false);
    const material = await api.createRecoveryKey(profile.id, settings?.key?.recovery_id ?? null, accepted);
    if (!current()) return;
    setCreated(material);
    await refresh();
  });
  const exportPackage = () => action(async (current) => {
    if (!created) return;
    const path = await save({ defaultPath: "sirinvpn-recovery.sirrec", filters: [{ name: t("settings.recovery.key.fileType"), extensions: ["sirrec"] }] });
    if (!path || !current()) return;
    await api.exportRecoveryPackage(created.key, path, password, accepted);
    if (!current()) return;
    setExportedPath(path);
    setPassword(""); setRepeat(""); setNotice(t("settings.recovery.key.saved"));
  });
  // The one-time key sits under the button that created it; it stays on screen if the connection drops.
  const keyPanel = created && <div className="invite-form">
        <p className="warning-note">{t("settings.recovery.key.warning")}</p>
        {!isAndroid && <Field label={t("settings.recovery.key.label")}><textarea rows={4} readOnly value={created.key} className="secret-code-output mono" /></Field>}
        <button className="secondary-button" disabled={busy} onClick={() => void action(async (current) => { await copyText(created.key); if (current()) setNotice(t("settings.recovery.key.copied")); })}><Copy size={17} />{t("settings.recovery.key.copy")}</button>
        <details><summary>{t("settings.recovery.key.qr")}</summary><SecretQr source={`data:image/svg+xml;charset=utf-8,${encodeURIComponent(created.qr_svg)}`} kind="recovery" code={created.key} /></details>
        <Field label={t("settings.recovery.key.password")} hint={t("settings.recovery.key.passwordHint")}><SecretInput type="password" autoComplete="new-password" value={password} onChange={(event) => setPassword(event.target.value)} /></Field>
        <Field label={t("settings.recovery.key.repeat")} error={repeat && repeat !== password ? t("common.error.passwordsDiffer") : undefined}><SecretInput type="password" autoComplete="new-password" value={repeat} onChange={(event) => setRepeat(event.target.value)} /></Field>
        <button className="secondary-button" disabled={busy || !accepted || [...password].length < 12 || password !== repeat} onClick={() => void exportPackage()}><DownloadSimple size={17} />{t("settings.recovery.key.save")}</button>
        <ConfirmationRow checked={retained} onChange={setRetained}>{t("settings.recovery.key.retained")}</ConfirmationRow>
        <ShareEncryptedFile uri={exportedPath} />
        <button className="primary-button" disabled={!retained || busy} onClick={() => { clearMaterial(); setNotice(t("settings.recovery.key.finished")); }}>{t("settings.recovery.key.finish")}</button>
      </div>;
  return <section ref={scope} className="settings-card" aria-label={t("settings.recovery.title")}>
    <h2>{t("settings.recovery.title")}</h2>
    <p>{t("settings.recovery.summary")}{info}</p>
    {infoPanel}
    {!connected ? <p>{t("common.error.needsConnection")}</p> : supported === false ? <p>{t("settings.recovery.unsupported")}</p> : settings ? <>
      <p>{settings.key ? t("settings.recovery.registered") : t("settings.recovery.none")}</p>
      {settings.enrollment_finishing && <p>{t("settings.recovery.finishing")}</p>}
      {!settings.can_issue_key && <p className="settings-note">{t("settings.recovery.cannotIssue")}</p>}
      {settings.can_issue_key && <>
        <label className="preference-checkbox"><input type="checkbox" checked={accepted} onChange={(event) => setAccepted(event.target.checked)} />
          <span>{t("settings.recovery.accept")}</span>
        </label>
        <button className="secondary-button" disabled={!accepted || busy || settings.enrollment_finishing} onClick={() => void create()}><Key size={17} />{busy ? t("common.state.working") : settings.key ? t("settings.recovery.replace") : t("settings.recovery.create")}</button>
      </>}
      {settings.key && owner && <button className="text-button danger-text" disabled={busy} onClick={() => void action(async (current) => {
        if (!await confirmAction({
          title: t("settings.recovery.revokeConfirm.title"),
          message: t("settings.recovery.revokeConfirm.message"),
          confirm: t("settings.recovery.revokeConfirm.confirm"),
        }) || !current()) return;
        const next = await api.revokeRecoveryKey(profile.id, settings.key!.recovery_id);
        if (current()) { setSettings(next); clearMaterial(); }
      })}>{t("settings.recovery.revoke")}</button>}
      {keyPanel}
      {owner && <details className="access-disclosure"><summary>{t("settings.recovery.admins.title")}</summary>
        <p>{t("settings.recovery.admins.summary")}</p>
        {admins.length ? admins.map((admin) => <label className="preference-checkbox" key={admin.id}>
          <input type="checkbox" checked={selected.includes(admin.id)} onChange={(event) => setSelected(event.target.checked ? [...selected, admin.id] : selected.filter((id) => id !== admin.id))} />
          <span>{admin.suspended ? t("common.separator.pair", { first: admin.name, second: t("settings.recovery.admins.suspended") }) : admin.name}</span>
        </label>) : <p>{t("settings.recovery.admins.none")}</p>}
        <button className="secondary-button" disabled={busy} onClick={() => void action(async (current) => {
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
          setNotice(t("settings.recovery.admins.saved"));
        })}>{t("settings.recovery.admins.save")}</button>
      </details>}
    </> : <p>{t("common.state.loading")}</p>}
    {!(connected && supported !== false && settings) && keyPanel}
    {notice && <p role="status">{notice}</p>}{error && <InlineError message={error} />}
  </section>;
}
