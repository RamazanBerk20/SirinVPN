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

// Current download preference only. This never stores or supplies signing trust.
const sourceKey = (serverId: string) => `sirinvpn.vps-update-source.${serverId}`;
export function rememberedReleaseSource(serverId: string): string {
  try {
    const value = window.localStorage.getItem(sourceKey(serverId)) ?? "";
    return validReleaseSource(value) ? value : "";
  } catch { return ""; }
}
export function rememberReleaseSource(serverId: string, source: string) {
  if (!validReleaseSource(source)) return;
  try { window.localStorage.setItem(sourceKey(serverId), source); } catch { /* Optional local preference. */ }
}
export function forgetReleaseSource(serverId: string) {
  try { window.localStorage.removeItem(sourceKey(serverId)); } catch { /* Storage may be unavailable. */ }
}
