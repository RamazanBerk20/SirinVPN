import { useEffect, useSyncExternalStore } from "react";
import { api } from "../../api";
import type { VpsBackupSchedule } from "../../types";
import { t } from "../../i18n";

const FIRST_CHECK_DELAY_MS = 60_000;
const CHECK_INTERVAL_MS = 15 * 60_000;
let schedules: VpsBackupSchedule[] = [];
let checking = false;
const listeners = new Set<() => void>();
const subscribe = (listener: () => void) => {
  listeners.add(listener);
  return () => void listeners.delete(listener);
};
const publish = (next: VpsBackupSchedule[]) => {
  schedules = next;
  listeners.forEach((listener) => listener());
};

export function updateVpsBackupSchedule(serverId: string, next: VpsBackupSchedule | null) {
  publish([...schedules.filter((item) => item.server_id !== serverId), ...(next ? [next] : [])]);
}

export async function refreshVpsBackupSchedules() {
  publish(await api.vpsBackupSchedules());
}

export function useVpsBackupSchedule(serverId: string) {
  return useSyncExternalStore(
    subscribe,
    () => schedules.find((item) => item.server_id === serverId) ?? null,
  );
}

/** Whole days since a UTC-seconds timestamp. */
export function backupAgeDays(at: number, now = Date.now()) {
  return Math.max(0, Math.floor((now / 1000 - at) / 86_400));
}

export function backupAge(at: number) {
  const days = backupAgeDays(at);
  return days === 0 ? t("vps.schedule.age.today") : t("vps.schedule.age.days", { count: days });
}

export function needsAttention(schedule: VpsBackupSchedule | null) {
  return Boolean(schedule && (schedule.last_failure || schedule.stale));
}

export function scheduleSummary(schedule: VpsBackupSchedule | null) {
  if (!schedule) return t("vps.schedule.summary.off");
  if (schedule.last_failure) return t("vps.schedule.summary.failed");
  if (!schedule.last_success) return t("vps.schedule.summary.pending");
  const age = backupAge(schedule.last_success);
  return schedule.stale ? t("vps.schedule.summary.stale", { age }) : t("vps.schedule.summary.ok", { age });
}

/**
 * Runs due backups one at a time while `ready` (this device is disconnected).
 * The backend checks again and records failures; a refused run is retried later.
 */
export function useScheduledVpsBackups(ready: boolean) {
  useEffect(() => {
    void refreshVpsBackupSchedules().catch(() => undefined);
    if (!ready) return;
    let active = true;
    const check = async () => {
      if (checking) return;
      checking = true;
      try {
        await refreshVpsBackupSchedules();
        for (const { server_id, due } of schedules) {
          if (!active) break;
          if (!due) continue;
          const next = await api.runScheduledVpsBackup(server_id, false).catch(() => null);
          if (next) updateVpsBackupSchedule(server_id, next);
        }
      } catch {
        // The schedule file was unreadable; the next check tries again.
      } finally {
        checking = false;
      }
    };
    // A minute's grace: opening the app to connect should not start a backup first.
    const first = window.setTimeout(() => void check(), FIRST_CHECK_DELAY_MS);
    const timer = window.setInterval(() => void check(), CHECK_INTERVAL_MS);
    return () => {
      active = false;
      window.clearTimeout(first);
      window.clearInterval(timer);
    };
  }, [ready]);
}
