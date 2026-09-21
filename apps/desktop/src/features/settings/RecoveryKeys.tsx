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
    } catch (reason) { if (current()) setError(errorMessage(reason, "Recovery settings could not be read.")); }
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
    try { await work(current); } catch (reason) { if (current()) setError(errorMessage(reason, "The recovery operation failed.")); }
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
    const path = await save({ defaultPath: "sirinvpn-recovery.sirrec", filters: [{ name: "Encrypted SirinVPN recovery package", extensions: ["sirrec"] }] });
    if (!path || !current()) return;
    await api.exportRecoveryPackage(created.key, path, password, accepted);
    if (!current()) return;
    setExportedPath(path);
    setPassword(""); setRepeat(""); setNotice("Encrypted recovery package saved. Keep its password separately.");
  });
  return <section ref={scope} className="settings-card" aria-label="Owner recovery">
    <h2>Owner recovery</h2>
    <p>Keep the recovery key or encrypted package offline. Using it to regain Owner access requires contacting your VPS.</p>
    <p className="settings-note">On a fresh client, choose Add server → Recovery key. No existing authorized device or ordinary VPN connection is required.</p>
    {!connected ? <p>Connect to configure recovery for this server.</p> : supported === false ? <p>Update VPS software to enable offline recovery keys.</p> : settings ? <>
      <p>{settings.key ? "An offline recovery key is registered. Its private material is never stored on the VPS." : "No offline recovery key is registered."}</p>
      {settings.enrollment_finishing && <p>A recovery enrollment is finishing. Wait one minute before creating another key.</p>}
      {settings.can_issue_key && <>
        <label className="preference-checkbox"><input type="checkbox" checked={accepted} onChange={(event) => setAccepted(event.target.checked)} />
          <span>I understand that anyone holding this key can replace every Owner device. Creating a replacement invalidates the previous key.</span>
        </label>
        <button className="secondary-button" disabled={!accepted || busy || settings.enrollment_finishing} onClick={() => void create()}><Key size={17} />{busy ? "Working" : settings.key ? "Replace recovery key" : "Create recovery key"}</button>
      </>}
      {settings.key && owner && <button className="text-button danger-text" disabled={busy} onClick={() => void action(async (current) => {
        if (!await confirmAction("Revoke this offline recovery key immediately? Its saved copies will stop working.") || !current()) return;
        const next = await api.revokeRecoveryKey(profile.id, settings.key!.recovery_id);
        if (current()) { setSettings(next); clearMaterial(); }
      })}>Revoke recovery key</button>}
      {owner && <details className="access-disclosure"><summary>Administrator recovery policy</summary>
        <p>Selected Admins can issue a new Owner recovery key, including while Owner devices still exist. Successful recovery clears these permissions; the recovered Owner can grant them again.</p>
        {admins.length ? admins.map((admin) => <label className="preference-checkbox" key={admin.id}>
          <input type="checkbox" checked={selected.includes(admin.id)} onChange={(event) => setSelected(event.target.checked ? [...selected, admin.id] : selected.filter((id) => id !== admin.id))} />
          <span>{admin.name}{admin.suspended ? " · currently suspended" : ""}</span>
        </label>) : <p>No Admins are configured. Administrator recovery stays disabled.</p>}
        <button className="secondary-button" disabled={busy} onClick={() => void action(async (current) => {
          const names = admins.filter(admin => selected.includes(admin.id)).map(admin => `${admin.name} (${admin.id})`).join(", ") || "No Administrators";
          if (!await confirmAction(`Allow these Administrators to issue Owner recovery keys: ${names}? Everyone else loses this permission.`) || !current()) return;
          const next = await api.updateRecoveryPolicy(profile.id, selected);
          if (!current()) return;
          setSettings(next); setSelected(next.policy.administrator_member_ids);
          setCreated((current) => current && current.recovery_id === next.key?.recovery_id ? current : null);
          setNotice("Administrator recovery policy saved.");
        })}>Save recovery policy</button>
      </details>}
    </> : <p>Reading current recovery settings…</p>}
      {created && <div className="invite-form">
        <p className="warning-note">Keep this key offline. It contains recovery secrets, works once, and cannot be retrieved again from the VPS.</p>
        {!isAndroid && <Field label="Recovery key"><textarea rows={4} readOnly value={created.key} className="secret-code-output mono" /></Field>}
        <button className="secondary-button" disabled={busy} onClick={() => void action(async (current) => { await copyText(created.key); if (current()) setNotice("Recovery key copied. Save it offline before confirming completion."); })}><Copy size={17} />Copy recovery key</button>
        <details><summary>Recovery QR code</summary><SecretQr source={`data:image/svg+xml;charset=utf-8,${encodeURIComponent(created.qr_svg)}`} kind="recovery" code={created.key} /></details>
        <Field label="Recovery package password" hint="At least 12 characters. The package contains the complete recovery key."><SecretInput type="password" autoComplete="new-password" value={password} onChange={(event) => setPassword(event.target.value)} /></Field>
        <Field label="Repeat package password"><SecretInput type="password" autoComplete="new-password" value={repeat} onChange={(event) => setRepeat(event.target.value)} /></Field>
        <button className="secondary-button" disabled={busy || !accepted || password.length < 12 || password !== repeat} onClick={() => void exportPackage()}><DownloadSimple size={17} />Save encrypted recovery package</button>
        <ConfirmationRow checked={retained} onChange={setRetained}>I have saved this recovery key or its encrypted package offline and can access it.</ConfirmationRow>
        <ShareEncryptedFile uri={exportedPath} />
        <button className="primary-button" disabled={!retained || busy} onClick={() => { clearMaterial(); setNotice("Recovery material acknowledged. The key has been cleared from this view."); }}>Finish recovery setup</button>
      </div>}
    {notice && <p role="status">{notice}</p>}{error && <InlineError message={error} />}
  </section>;
}
