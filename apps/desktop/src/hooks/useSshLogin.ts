import { useCallback, useEffect, useReducer, useRef } from "react";
import { api } from "../api";
import { notify } from "../components/Toasts";
import { validateHost } from "../format";
import { errorMessage } from "../lib/errors";
import { t } from "../i18n";
import type { SshCredentials, SshLoginInput } from "../types";
import { initialSshLogin, sshLoginReducer, type SshLoginDraft } from "./sshLoginMachine";

export interface PreparedSshLogin {
  credentials: SshCredentials;
  /** Remembers the login, if asked to; call it only after the operation that used it succeeded. */
  save: () => Promise<void>;
}
const noSave = async () => {};

export function useSshLogin(host: string, active = true) {
  const destination = host.trim();
  const target = active && validateHost(destination) ? destination : null;
  const [state, dispatch] = useReducer(sshLoginReducer, initialSshLogin);
  const latest = useRef(state);
  latest.current = state;
  useEffect(() => {
    dispatch({ type: "destination", host: target });
  }, [target]);

  // Avoid asking the wallet about each partial hostname while typing; announce only a slow read.
  const lookupHost = state.kind === "looking" ? state.host : null;
  const lookupSeq = state.kind === "looking" ? state.seq : 0;
  useEffect(() => {
    if (lookupHost === null) return;
    const seq = lookupSeq;
    let progressTimer: number | undefined;
    const timer = window.setTimeout(() => {
      progressTimer = window.setTimeout(() => dispatch({ type: "slow", seq }), 500);
      void api.getSshLogin(lookupHost)
        .then(login => dispatch({ type: "found", seq, login }))
        .catch(reason => dispatch({ type: "lookupFailed", seq, message: errorMessage(reason, t("ssh.error.readSaved")) }))
        .finally(() => window.clearTimeout(progressTimer));
    }, 250);
    return () => { window.clearTimeout(timer); window.clearTimeout(progressTimer); };
  }, [lookupHost, lookupSeq]);

  const { draft } = state;
  const loading = state.kind === "looking";
  const forgetting = state.kind === "forgetting";
  const usingSaved = state.kind === "saved" || state.kind === "forgetting" && state.from === "saved";
  const parsedPort = Number(draft.port);
  const portValid = Number.isInteger(parsedPort) && parsedPort > 0 && parsedPort <= 65_535;
  const valid = target !== null && !loading && !forgetting && state.kind !== "idle" &&
    draft.username.trim().length > 0 && portValid &&
    (usingSaved || draft.auth === "agent" ||
      (draft.auth === "password" && draft.password.length > 0) ||
      (draft.auth === "private_key" && draft.keyPath.trim().length > 0));

  /** What is still missing, for the line beside a disabled Continue. */
  const missing = valid || loading || forgetting || !active ? null
    : !draft.username.trim() ? t("ssh.missing.username")
    : !portValid ? t("ssh.missing.port")
    : draft.auth === "password" ? t("ssh.missing.password")
    : draft.auth === "private_key" ? t("ssh.missing.key")
    : null;

  /**
   * The credentials for one operation, and the save of a new login to remember. The caller calls
   * `save` only once that operation worked, so a login that failed is never stored.
   */
  const prepare = (fingerprint: string): PreparedSshLogin => {
    const current = latest.current;
    if (target === null || current.kind === "idle") throw new Error(t("ssh.error.cancelled"));
    if (!valid) throw new Error(t("ssh.error.invalidLogin"));
    if (usingSaved) {
      return { credentials: { username: draft.username.trim(), ssh_port: parsedPort, authentication: "saved", password: null,
        private_key_path: null, private_key_passphrase: null, sudo_password: null, host_key_sha256: fingerprint }, save: noSave };
    }
    const credentials: SshCredentials = {
      username: draft.username.trim(),
      ssh_port: parsedPort,
      authentication: draft.auth,
      password: draft.auth === "password" ? draft.password : null,
      private_key_path: draft.auth === "private_key" ? draft.keyPath.trim() : null,
      private_key_passphrase: draft.auth === "private_key" && draft.keyPassphrase ? draft.keyPassphrase : null,
      sudo_password: draft.username.trim() === "root" || !draft.sudoPassword ? null : draft.sudoPassword,
      host_key_sha256: fingerprint,
    };
    if (!draft.remember) return { credentials, save: noSave };
    const input: SshLoginInput = { host: target, ...credentials };
    let saved = false;
    // A failed save never fails the operation that already worked.
    const save = async () => {
      if (saved) return;
      saved = true;
      try {
        dispatch({ type: "committed", seq: current.seq, login: await api.saveSshLogin(input) });
      } catch (reason) {
        notify(errorMessage(reason, t("ssh.error.save")), "error");
      }
    };
    return { credentials, save };
  };

  const forget = async () => {
    const current = latest.current;
    if (current.kind === "idle") return;
    dispatch({ type: "forget" });
    try {
      await api.forgetSshLogin(current.host);
      dispatch({ type: "forgotten", seq: current.seq });
    } catch (reason) {
      dispatch({ type: "forgetFailed", seq: current.seq, message: errorMessage(reason, t("ssh.error.forget")) });
    }
  };

  const set = <K extends keyof SshLoginDraft>(key: K) => (value: SshLoginDraft[K]) => dispatch({ type: "change", patch: { [key]: value } });
  const clearSecrets = useCallback(() => dispatch({ type: "clearSecrets" }), []);

  return {
    state: state.kind,
    username: draft.username, setUsername: set("username"),
    port: draft.port, setPort: set("port"),
    auth: draft.auth, setAuth: set("auth"),
    password: draft.password, setPassword: set("password"),
    keyPath: draft.keyPath, setKeyPath: set("keyPath"),
    keyPassphrase: draft.keyPassphrase, setKeyPassphrase: set("keyPassphrase"),
    sudoPassword: draft.sudoPassword, setSudoPassword: set("sudoPassword"),
    remember: draft.remember, setRemember: set("remember"),
    saved: state.kind === "saved" || state.kind === "editing" || state.kind === "forgetting" ? state.login : null,
    usingSaved,
    loading,
    checkingSavedLogin: state.kind === "looking" && state.slow,
    forgetting,
    error: state.kind === "lookupFailed" ? state.message : state.kind === "saved" || state.kind === "editing" ? state.error : null,
    valid,
    missing,
    retry: () => dispatch({ type: "retry" }),
    prepare,
    clearSecrets,
    forget,
    edit: () => dispatch({ type: "edit" }),
    reuse: () => dispatch({ type: "reuse" }),
  };
}
