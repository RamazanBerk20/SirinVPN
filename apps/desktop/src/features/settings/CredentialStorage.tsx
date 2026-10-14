import { useEffect, useRef, useState } from "react";
import { invoke } from "../../platform";
import { InlineError } from "../../components/ui";
import { t, type MessageKey } from "../../i18n";

interface Snapshot {
  supported: boolean;
  policy: "secure_store_required" | "allow_private_file";
  pending_cleanup: number;
  profiles: { server_id: string; name: string; storage: {
    backend: string; protection: string; availability: string; cleanup_pending: boolean;
  } }[];
}

const protectionLabels = new Map<string, MessageKey>([
  ["system_secure_store", "settings.credentials.protection.keyring"],
  ["permissions_only", "settings.credentials.protection.file"],
]);
const availabilityLabels = new Map<string, MessageKey>([
  ["available", "settings.credentials.availability.available"],
  ["absent", "settings.credentials.availability.absent"],
  ["invalid", "settings.credentials.availability.invalid"],
  ["unavailable", "settings.credentials.availability.unavailable"],
]);

function storageSummary({ protection, availability }: Snapshot["profiles"][number]["storage"]): string {
  return t("common.separator.pair", {
    first: t(protectionLabels.get(protection) ?? "settings.credentials.protection.unverified"),
    second: t(availabilityLabels.get(availability) ?? "common.state.unknown"),
  });
}

export function CredentialStorage() {
  const [snapshot, setSnapshot] = useState<Snapshot | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [consent, setConsent] = useState(false);
  const generation = useRef(0);
  const inFlight = useRef(false);
  async function run(action?: string, serverId?: string) {
    if (inFlight.current) return;
    inFlight.current = true;
    const request = ++generation.current;
    setBusy(true); setError("");
    try {
      const next = await invoke<Snapshot>("credential_storage", { action, serverId });
      if (request === generation.current) { setSnapshot(next); setConsent(false); }
    } catch (cause) {
      if (request === generation.current) {
        setError(typeof cause === "string" ? cause : t("settings.credentials.loadFailed"));
        // A failed action can have committed provenance or partial cleanup.
        if (action) {
          try {
            const current = await invoke<Snapshot>("credential_storage", {});
            if (request === generation.current) setSnapshot(current);
          } catch {
            if (request === generation.current) setSnapshot(null);
          }
        } else {
          setSnapshot(null);
        }
      }
    } finally {
      if (request === generation.current) { inFlight.current = false; setBusy(false); }
    }
  }
  useEffect(() => {
    void run();
    return () => { ++generation.current; inFlight.current = false; };
  }, []);
  if (snapshot?.supported === false) return null;
  return <section className="settings-card" aria-busy={busy}>
    <h2>{t("settings.credentials.title")}</h2>
    <p>{t("settings.credentials.summary")}</p>
    {error && <InlineError message={error} />}
    {!snapshot && <button className="secondary-button" disabled={busy} onClick={() => void run()}>{busy ? t("common.state.checking") : t("common.action.retry")}</button>}
    {snapshot && <>
      <p role="status">{snapshot.policy === "secure_store_required" ? t("settings.credentials.policy.secure") : t("settings.credentials.policy.fileAllowed")}</p>
      {snapshot.policy === "secure_store_required" ? <>
        <label className="preference-row"><span>{t("settings.credentials.consent")}</span>
          <input type="checkbox" role="switch" checked={consent} disabled={busy} onChange={event => setConsent(event.target.checked)} /></label>
        <button className="secondary-button" disabled={busy || !consent} onClick={() => void run("allow_private_file")}>{t("settings.credentials.allowFile")}</button>
      </> : <button className="secondary-button" disabled={busy} onClick={() => void run("require_secure")}>{t("settings.credentials.requireKeyring")}</button>}
      {snapshot.profiles.map(profile => <div className="preference-row" key={profile.server_id}>
        <span><strong>{profile.name}</strong><small>{storageSummary(profile.storage)}</small>
          {profile.storage.cleanup_pending && <small>{t("settings.credentials.cleanupIncomplete")}</small>}</span>
        {profile.storage.availability === "available" && (profile.storage.backend !== "keyring" || profile.storage.cleanup_pending) &&
          <button className="secondary-button" disabled={busy} onClick={() => void run("migrate", profile.server_id)}>{t("settings.credentials.move")}</button>}
      </div>)}
      {snapshot.pending_cleanup > 0 && <p>{t("settings.credentials.pendingCleanup")}</p>}
      <div className="settings-action-row">
        <button className="secondary-button" disabled={busy} onClick={() => void run()}>{t("settings.credentials.refresh")}</button>
        {snapshot.pending_cleanup > 0 && <button className="secondary-button" disabled={busy} onClick={() => void run("retry_cleanup")}>{t("settings.credentials.retryCleanup")}</button>}
      </div>
    </>}
  </section>;
}
