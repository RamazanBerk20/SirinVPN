import type { SshLoginInput } from "../../types";

export type VpsReleaseOperation =
  | { action: "status" }
  | { action: "check"; source: string; channel: "stable" | "preview" }
  | { action: "install"; manifest_sha256: string }
  | { action: "rollback"; confirmed: boolean }
  | { action: "configure"; enabled: boolean; source: string | null }
  | { action: "recover" };
export interface VpsReleaseInput { server_id: string; ssh: SshLoginInput; operation: VpsReleaseOperation }
export interface VpsBaselineAccess { server_id: string; ssh: SshLoginInput }
export interface VpsBaselineCandidate {
  release_version: string; release_sequence: string; channel: string; security_update: boolean; manifest_sha256: string;
  artifact: { sha256: string; target: string; size_bytes: number };
}
export interface VpsSecurityPolicy { schema_version: number; enabled: boolean; source: string | null; channel: "stable" }
export interface VpsInstalledRelease {
  active_release_version: string;
  active_release_sequence: string;
  highest_accepted_release_sequence: string;
  channel: "stable" | "preview";
  active_artifact: { sha256: string; target: string };
}
export interface VpsReleaseStatus {
  release: { installed: VpsInstalledRelease | null; rollback_version: string | null; recovery_pending: boolean };
  security_updates: VpsSecurityPolicy;
  automatic_outcome: "disabled" | "baseline_required" | "no_new_security_release" | "installed" | "failed" | null;
  installed_binary_matches: boolean;
}
export interface VpsReleaseCandidate {
  release_version: string;
  release_sequence: string;
  security_update: boolean;
  channel: "stable" | "preview";
  manifest_sha256: string;
  artifact_sha256: string;
  artifact_target: string;
  artifact_size_bytes: number;
  action: "initialize" | "upgrade" | "rollback" | "rebind" | "already_bound";
  can_install: boolean;
  baseline_required: boolean;
}

export function validReleaseSource(source: string) {
  if (!source || source.length > 2048) return false;
  try {
    const url = new URL(source);
    return url.protocol === "https:" && !url.username && !url.password && !url.search && !url.hash && url.pathname.endsWith("/");
  } catch { return false; }
}

/** Adds the trailing "/" a release folder needs, when that is all that is missing. */
export function completeReleaseSource(source: string) {
  const trimmed = source.trim();
  return trimmed && !trimmed.endsWith("/") && validReleaseSource(`${trimmed}/`) ? `${trimmed}/` : trimmed;
}

// Current download preference only. This never stores or supplies signing trust.
const VPS_SOURCE_PREFIX = "sirinvpn.vps-update-source.";
const APP_SOURCE_KEY = "sirinvpn.app-update-source";
const sourceKey = (serverId: string) => `${VPS_SOURCE_PREFIX}${serverId}`;
const stored = (key: string | null) => {
  const value = key ? window.localStorage.getItem(key) ?? "" : "";
  return validReleaseSource(value) ? value : "";
};
// One release folder holds the app and the server packages, so each can start from the other's source.
const anyVpsSource = () => {
  for (let index = 0; index < window.localStorage.length; index += 1) {
    const key = window.localStorage.key(index);
    const value = key?.startsWith(VPS_SOURCE_PREFIX) ? stored(key) : "";
    if (value) return value;
  }
  return "";
};
export function rememberedReleaseSource(serverId: string): string {
  try { return stored(sourceKey(serverId)) || stored(APP_SOURCE_KEY); } catch { return ""; }
}
export function rememberedAppReleaseSource(): string {
  try { return stored(APP_SOURCE_KEY) || anyVpsSource(); } catch { return ""; }
}
export function rememberAppReleaseSource(source: string) {
  if (!validReleaseSource(source)) return;
  try { window.localStorage.setItem(APP_SOURCE_KEY, source); } catch { /* Optional local preference. */ }
}
export function rememberReleaseSource(serverId: string, source: string) {
  if (!validReleaseSource(source)) return;
  try { window.localStorage.setItem(sourceKey(serverId), source); } catch { /* Optional local preference. */ }
}
export function forgetReleaseSource(serverId: string) {
  try { window.localStorage.removeItem(sourceKey(serverId)); } catch { /* Storage may be unavailable. */ }
}
