import { useEffect, useRef, useState } from "react";
import { invoke } from "../../platform";
import { InlineError } from "../../components/ui";

interface Snapshot {
  supported: boolean;
  policy: "secure_store_required" | "allow_private_file";
  pending_cleanup: number;
  profiles: { server_id: string; name: string; storage: {
    backend: string; protection: string; availability: string; cleanup_pending: boolean;
  } }[];
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
        setError(typeof cause === "string" ? cause : "Credential storage status is unavailable. Retry after unlocking the system keyring.");
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
    <h2>Credential storage</h2>
    <p>New credentials require the system keyring by default. Existing profiles keep their current storage until you migrate them.</p>
    {error && <InlineError message={error} />}
    {!snapshot && <button className="secondary-button" disabled={busy} onClick={() => void run()}>{busy ? "Reading storage…" : "Retry storage status"}</button>}
    {snapshot && <>
      <p role="status">{snapshot.policy === "secure_store_required" ? "Secure storage required for new credentials." : "Permission-protected file fallback allowed. These files are not encrypted by SirinVPN."}</p>
      {snapshot.policy === "secure_store_required" ? <>
        <label className="preference-row"><span>I allow unencrypted, permission-protected identity files when the keyring is unavailable.</span>
          <input type="checkbox" role="switch" checked={consent} disabled={busy} onChange={event => setConsent(event.target.checked)} /></label>
        <button className="secondary-button" disabled={busy || !consent} onClick={() => void run("allow_private_file")}>Allow file fallback</button>
      </> : <button className="secondary-button" disabled={busy} onClick={() => void run("require_secure")}>Require secure storage</button>}
      {snapshot.profiles.map(profile => <div className="preference-row" key={profile.server_id}>
        <span><strong>{profile.name}</strong><small>{profile.storage.protection === "system_secure_store" ? "System keyring" : profile.storage.protection === "permissions_only" ? "Permission-protected file · not encrypted" : "Storage protection unverified"} · {profile.storage.availability.replaceAll("_", " ")}</small>
          {profile.storage.cleanup_pending && <small>Credential cleanup is incomplete.</small>}</span>
        {profile.storage.availability === "available" && (profile.storage.backend !== "keyring" || profile.storage.cleanup_pending) &&
          <button className="secondary-button" disabled={busy} onClick={() => void run("migrate", profile.server_id)}>Migrate to keyring</button>}
      </div>)}
      {snapshot.pending_cleanup > 0 && <p>Local credential cleanup is pending. Unlock the keyring and retry. This does not revoke access on the server.</p>}
      <div className="settings-action-row">
        <button className="secondary-button" disabled={busy} onClick={() => void run()}>Refresh storage</button>
        {snapshot.pending_cleanup > 0 && <button className="secondary-button" disabled={busy} onClick={() => void run("retry_cleanup")}>Retry credential cleanup</button>}
      </div>
    </>}
  </section>;
}
