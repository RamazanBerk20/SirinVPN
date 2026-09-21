import { useEffect, useId, useRef, useState } from "react";
import { open } from "../../lib/nativeDialog";
import { api } from "../../api";
import { errorMessage } from "../../lib/errors";
import type { LocalTunnelStatus } from "../../types";

export function ApplicationLauncher({ serverId, local, busy }: {
  serverId: string;
  local: LocalTunnelStatus;
  busy: boolean;
}) {
  const [executable, setExecutable] = useState("");
  const [argumentsText, setArgumentsText] = useState("");
  const [launching, setLaunching] = useState(false);
  const [notice, setNotice] = useState("");
  const [error, setError] = useState<string | null>(null);
  const generation = useRef(0);
  const argumentsHelpId = useId();
  const windows = local.application_routing_backend === "windows_bind_redirect";
  useEffect(() => {
    ++generation.current;
    setExecutable("");
    setArgumentsText("");
    setNotice("");
    setError(null);
    return () => { ++generation.current; };
  }, [serverId]);
  const ready = local.server_id === serverId && local.state === "connected" &&
    local.routing_mode === "selected_applications" && local.application_routing_ready === true &&
    local.supervisor_status_known === true;
  const choose = async () => {
    const current = generation.current;
    try {
      const path = await open({ title: "Choose a native application executable", ...(windows
        ? { filters: [{ name: "Windows executable", extensions: ["exe"] }] }
        : { defaultPath: "/usr/bin" }), multiple: false, directory: false });
      if (current === generation.current && typeof path === "string") setExecutable(path);
    } catch (reason) {
      if (current === generation.current) setError(errorMessage(reason, "The application chooser could not open."));
    }
  };
  const launch = async () => {
    if (!ready || busy || launching || !executable.trim()) return;
    const current = generation.current;
    setLaunching(true);
    setNotice("");
    setError(null);
    try {
      const result = await api.launchVpnApplication(serverId, executable.trim(), argumentsText.split("\n").filter((arg) => arg.length > 0));
      if (current === generation.current) setNotice(result.completed
        ? "The command finished. No running app was confirmed."
        : windows ? "The executable is selected and a new process has started. Disconnect clears the current selection."
        : "A new process was launched in the VPN. Close and relaunch it here after disconnecting.");
    } catch (reason) {
      if (current === generation.current) setError(errorMessage(reason, "The application could not be launched in the VPN."));
    } finally {
      setLaunching(false);
    }
  };
  return (
    <fieldset className="choice-fieldset application-launcher">
      <legend>Launch an application in the VPN</legend>
      <p>{windows ? "Selected executables under your Windows account use the VPN for IPv4 TCP and UDP. Their IPv6 is blocked. System DNS uses the VPS; other apps keep their usual routes."
        : "Only new processes launched here use this tunnel. Their DNS uses the VPS. Other apps and system DNS keep their usual network settings."}</p>
      <p>{windows ? "Close existing instances first. Choose a native .exe on a fixed local drive. Select each separate executable that handles networking; helper apps and Windows services are not selected automatically. Apps bound to another network address cannot connect."
        : "Close existing instances first. Choose a native executable; Flatpak, Snap, portal and desktop-service launchers are unsupported. Apps that hand work to a separate running service may not be compatible."}</p>
      {!ready && <p className="settings-note">Save Selected applications mode and connect this server before launching.</p>}
      <label className="route-list-field">
        <span>Application executable</span>
        <input value={executable} onChange={(event) => setExecutable(event.target.value)} placeholder={windows ? "C:\\Program Files\\Application\\app.exe" : "/usr/bin/application"} disabled={launching || busy} autoComplete="off" spellCheck={false} />
      </label>
      <button type="button" className="secondary-button" onClick={() => void choose()} disabled={launching || busy}>Choose application</button>
      <details className="inline-disclosure">
        <summary>Launch arguments</summary>
        <label className="route-list-field">
          <span>One argument per line</span>
          <textarea value={argumentsText} onChange={(event) => setArgumentsText(event.target.value)} rows={3} disabled={launching || busy} spellCheck={false} aria-describedby={argumentsHelpId} />
        </label>
        <small id={argumentsHelpId}>Spaces stay within the same argument. Omit shell quotes. {windows
          ? "Arguments are not saved. Up to 24 executable selections stay with this VPN session for recovery, until you disconnect."
          : "Selections and arguments are not saved."}</small>
      </details>
      <p className="settings-note">{windows
        ? "Keep the kill switch on and local-network access off. Selected executables stay blocked outside the VPN during interruption or Pause. Disconnect releases their protection and clears the selection."
        : "Launched apps cannot fall back to the internet outside the VPN, even with the optional kill switch off. Disconnect leaves these processes open with their network link disabled."}</p>
      <button type="button" className="primary-button" onClick={() => void launch()} disabled={!ready || busy || launching || !executable.trim()}>{launching ? "Launching…" : "Launch in VPN"}</button>
      {notice && <p role="status">{notice}</p>}
      {error && <p role="alert">{error}</p>}
    </fieldset>
  );
}
