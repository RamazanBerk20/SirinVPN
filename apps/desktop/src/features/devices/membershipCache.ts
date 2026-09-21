import type { MembershipSnapshot } from "../../types";

type Entry = { value?: MembershipSnapshot; at?: number; revision: number; pending?: Promise<MembershipSnapshot> };
const entries = new Map<string, Entry>();

export function clearMembershipCache() { entries.clear(); }
export function cachedMembership(key: string) { return entries.get(key); }
function entry(key: string): Entry {
  const existing = entries.get(key);
  if (existing) return existing;
  if (entries.size >= 16) entries.delete(entries.keys().next().value!);
  const next = { revision: 0 };
  entries.set(key, next);
  return next;
}
export function retainMembership(key: string, value: MembershipSnapshot) {
  const current = entry(key);
  current.revision++;
  current.value = value;
  current.at = Date.now();
}
export function readMembership(key: string, load: () => Promise<MembershipSnapshot>) {
  const current = entry(key);
  if (current.pending) return current.pending;
  const revision = current.revision;
  const pending = load().then(value => {
    if (entries.get(key) === current && current.revision === revision) {
      current.value = value; current.at = Date.now();
    }
    return current.revision === revision ? value : current.value!;
  }).finally(() => { if (current.pending === pending) current.pending = undefined; });
  current.pending = pending;
  return pending;
}
export function withoutLiveActivity(value: MembershipSnapshot): MembershipSnapshot {
  return { ...value, members: value.members.map(member => ({ ...member,
    devices: member.devices.map(device => ({ ...device, recent_handshake: undefined })),
  })) };
}
