import type { SavedSshLogin } from "../types";

/** What the user typed or what a saved login filled in. Secrets never outlive an operation. */
export interface SshLoginDraft {
  username: string;
  port: string;
  auth: SavedSshLogin["authentication"];
  password: string;
  keyPath: string;
  keyPassphrase: string;
  sudoPassword: string;
  remember: boolean;
}

/**
 * The saved-login lookup for one destination. `seq` ties async results to the lookup that asked.
 * - idle: no valid destination (or the form is inactive)
 * - looking: reading the keyring; `slow` once the read takes long enough to announce
 * - saved: the saved login is used
 * - editing: the user enters a login; `login` is the saved one they can go back to
 * - forgetting: removing the saved login; `from` is where a failure returns
 * - lookupFailed: the keyring couldn't be read; the user can still enter a login or retry
 */
export type SshLoginState =
  | { kind: "idle"; draft: SshLoginDraft }
  | { kind: "looking"; host: string; seq: number; slow: boolean; draft: SshLoginDraft }
  | { kind: "saved"; host: string; seq: number; login: SavedSshLogin; draft: SshLoginDraft; error: string | null }
  | { kind: "editing"; host: string; seq: number; login: SavedSshLogin | null; draft: SshLoginDraft; error: string | null }
  | { kind: "forgetting"; host: string; seq: number; login: SavedSshLogin | null; from: "saved" | "editing" | "lookupFailed"; draft: SshLoginDraft }
  | { kind: "lookupFailed"; host: string; seq: number; message: string; draft: SshLoginDraft };

export type SshLoginAction =
  /** A new destination (null: none or inactive). Resets the draft. */
  | { type: "destination"; host: string | null }
  /** Read the keyring again for the same destination, keeping what was typed. */
  | { type: "retry" }
  | { type: "slow"; seq: number }
  | { type: "found"; seq: number; login: SavedSshLogin | null }
  | { type: "lookupFailed"; seq: number; message: string }
  | { type: "change"; patch: Partial<SshLoginDraft> }
  | { type: "clearSecrets" }
  | { type: "edit" }
  | { type: "reuse" }
  | { type: "forget" }
  | { type: "forgotten"; seq: number }
  | { type: "forgetFailed"; seq: number; message: string }
  /** A login that just worked was saved. */
  | { type: "committed"; seq: number; login: SavedSshLogin };

export const newDraft = (): SshLoginDraft => ({
  username: "root", port: "22", auth: "password", password: "", keyPath: "", keyPassphrase: "", sudoPassword: "", remember: true,
});
const withoutSecrets = (draft: SshLoginDraft): SshLoginDraft => ({ ...draft, password: "", keyPassphrase: "", sudoPassword: "" });
const fromLogin = (draft: SshLoginDraft, login: SavedSshLogin): SshLoginDraft => ({
  ...withoutSecrets(draft), username: login.username, port: String(login.ssh_port), auth: login.authentication, keyPath: login.private_key_path ?? "",
});

export const initialSshLogin: SshLoginState = { kind: "idle", draft: newDraft() };

export function sshLoginReducer(state: SshLoginState, action: SshLoginAction): SshLoginState {
  const seq = state.kind === "idle" ? 0 : state.seq;
  // Results of a lookup, forget or save that no longer belong to this destination are dropped.
  if ("seq" in action && (state.kind === "idle" || action.seq !== seq)) return state;
  switch (action.type) {
    case "destination":
      return action.host === null ? { kind: "idle", draft: newDraft() }
        : { kind: "looking", host: action.host, seq: seq + 1, slow: false, draft: newDraft() };
    case "retry":
      return state.kind === "idle" ? state : { kind: "looking", host: state.host, seq: seq + 1, slow: false, draft: state.draft };
    case "slow":
      return state.kind === "looking" ? { ...state, slow: true } : state;
    case "found":
      if (state.kind !== "looking") return state;
      return action.login
        ? { kind: "saved", host: state.host, seq, login: action.login, draft: fromLogin(state.draft, action.login), error: null }
        : { kind: "editing", host: state.host, seq, login: null, draft: state.draft, error: null };
    case "lookupFailed":
      return state.kind === "looking" ? { kind: "lookupFailed", host: state.host, seq, message: action.message, draft: state.draft } : state;
    case "change":
      return { ...state, draft: { ...state.draft, ...action.patch } };
    case "clearSecrets":
      return { ...state, draft: withoutSecrets(state.draft) };
    case "edit":
      return state.kind === "saved" ? { kind: "editing", host: state.host, seq, login: state.login, draft: withoutSecrets(state.draft), error: null } : state;
    case "reuse":
      return state.kind === "editing" && state.login
        ? { kind: "saved", host: state.host, seq, login: state.login, draft: fromLogin(state.draft, state.login), error: null } : state;
    case "forget":
      // After a failed keyring read the saved login may be unreadable; forgetting it is the way out.
      return state.kind === "saved" || state.kind === "editing" && state.login || state.kind === "lookupFailed"
        ? { kind: "forgetting", host: state.host, seq, login: state.kind === "lookupFailed" ? null : state.login, from: state.kind, draft: state.draft } : state;
    case "forgotten":
      return state.kind === "forgetting"
        ? { kind: "editing", host: state.host, seq, login: null, draft: withoutSecrets(state.draft), error: null } : state;
    case "forgetFailed":
      if (state.kind !== "forgetting") return state;
      if (state.from === "saved" && state.login) return { kind: "saved", host: state.host, seq, login: state.login, draft: state.draft, error: action.message };
      if (state.from === "editing") return { kind: "editing", host: state.host, seq, login: state.login, draft: state.draft, error: action.message };
      return { kind: "lookupFailed", host: state.host, seq, message: action.message, draft: state.draft };
    case "committed":
      return state.kind === "idle" || state.kind === "looking" || state.kind === "forgetting" ? state
        : { kind: "saved", host: state.host, seq, login: action.login, draft: fromLogin(state.draft, action.login), error: null };
  }
}
