import type { MembershipSnapshot } from "../../types";
import type { Saved } from "./model";

/**
 * The last list read for each server and device, kept for this app session only, so the page can
 * show it read-only while disconnected. Nothing is written to disk.
 */
const lastKnown = new Map<string, Saved>();

export function rememberMembership(key: string, snapshot: MembershipSnapshot) {
  lastKnown.delete(key);
  if (lastKnown.size >= 16) lastKnown.delete(lastKnown.keys().next().value!);
  lastKnown.set(key, { snapshot, at: Date.now() });
}

export const savedMembership = (key: string): Saved | null => lastKnown.get(key) ?? null;

/**
 * Called when the tunnel goes down. The saved lists stay: the disconnected page shows them,
 * marked with when they were read, and every read after reconnecting replaces them.
 */
export function clearMembershipCache() {}

/** For tests. */
export function forgetMembership() { lastKnown.clear(); }
