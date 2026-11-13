import * as Dialog from "@radix-ui/react-dialog";
import { useEffect, useId, useState } from "react";
import { api } from "../../api";
import { DialogContent } from "../../components/DialogContent";
import { Busy } from "../../components/OperationResult";
import { SecretInput } from "../../components/SecretInput";
import { notify } from "../../components/Toasts";
import { Field, InlineError } from "../../components/ui";
import { t } from "../../i18n";
import { errorMessage } from "../../lib/errors";
import { open as openDialog } from "../../lib/nativeDialog";
import type { ServerProfile, VpsBackupSchedule } from "../../types";
import {
  backupAge,
  refreshVpsBackupSchedules,
  updateVpsBackupSchedule,
  useVpsBackupSchedule,
} from "./vpsBackupSchedules";

const intervals = [
  [1, "vps.schedule.daily"],
  [7, "vps.schedule.weekly"],
  [30, "vps.schedule.monthly"],
] as const;

export function VpsBackupScheduleDialog({
  profile,
  open,
  onOpenChange,
  disconnected,
}: {
  profile: ServerProfile;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  disconnected: boolean;
}) {
  const schedule = useVpsBackupSchedule(profile.id);
  const [busy, setBusy] = useState(false);
  return (
    <Dialog.Root open={open} onOpenChange={(next) => !busy && onOpenChange(next)}>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        {/* Mounted per opening so the form starts from the saved schedule. */}
        {open && (
          <ScheduleForm
            profile={profile}
            schedule={schedule}
            disconnected={disconnected}
            busy={busy}
            setBusy={setBusy}
          />
        )}
      </Dialog.Portal>
    </Dialog.Root>
  );
}

type Task = "folder" | "save" | "run" | "off";

function ScheduleForm({
  profile,
  schedule,
  disconnected,
  busy,
  setBusy,
}: {
  profile: ServerProfile;
  schedule: VpsBackupSchedule | null;
  disconnected: boolean;
  busy: boolean;
  setBusy: (busy: boolean) => void;
}) {
  const formId = useId();
  const [folder, setFolder] = useState(schedule?.folder ?? "");
  const [keep, setKeep] = useState(String(schedule?.keep ?? 4));
  const [interval, setIntervalDays] = useState<number>(schedule?.interval_days ?? 7);
  const [password, setPassword] = useState("");
  const [repeat, setRepeat] = useState("");
  const [task, setTask] = useState<Task | null>(null);
  const [savedLogin, setSavedLogin] = useState<boolean | null>(null);
  const [error, setError] = useState<{ message: string; retry?: () => void } | null>(null);

  useEffect(() => {
    let active = true;
    void refreshVpsBackupSchedules().catch(() => undefined);
    api.getSshLogin(profile.endpoint.host).then(
      (login) => active && setSavedLogin(Boolean(login)),
      () => active && setSavedLogin(false),
    );
    return () => {
      active = false;
    };
  }, [profile.endpoint.host]);

  const keepCount = Number(keep);
  const keepValid = Number.isInteger(keepCount) && keepCount >= 1 && keepCount <= 30;
  const passwordValid = password
    ? [...password].length >= 12 && password === repeat
    : Boolean(schedule) && !repeat;
  const valid = folder.length > 0 && keepValid && passwordValid;
  const blocker = !folder ? t("vps.schedule.missing.folder")
    : !keepValid ? t("vps.schedule.keepHint")
    : passwordValid ? null
    : !password ? t("vps.backup.missing.password")
    : [...password].length < 12 ? t("vps.backup.missing.password") : t("vps.backup.missing.repeat");

  const run = async (kind: Task, action: () => Promise<void>, fallback: string, retry?: () => void) => {
    setBusy(true);
    setTask(kind);
    setError(null);
    try {
      await action();
    } catch (reason) {
      setError({ message: errorMessage(reason, fallback), retry });
    } finally {
      setBusy(false);
      setTask(null);
    }
  };

  const chooseFolder = () =>
    run("folder", async () => {
      const selected = await openDialog({
        purpose: "vps_backup_folder",
        directory: true,
        title: t("vps.schedule.folderDialogTitle"),
      });
      if (typeof selected === "string") setFolder(selected);
    }, t("vps.common.error.picker"));

  const save = () =>
    run("save", async () => {
      updateVpsBackupSchedule(
        profile.id,
        await api.setVpsBackupSchedule({
          server_id: profile.id,
          folder,
          keep: keepCount,
          interval_days: interval,
          ...(password ? { backup_password: password } : {}),
        }),
      );
      setPassword("");
      setRepeat("");
      notify(t("vps.schedule.saved"));
    }, t("vps.schedule.error.save"), () => void save());

  const backUpNow = () =>
    run("run", async () => {
      const before = schedule?.last_success ?? 0;
      const next = await api.runScheduledVpsBackup(profile.id, true);
      updateVpsBackupSchedule(profile.id, next);
      // A failed run is recorded in the schedule and shown above, not thrown.
      if ((next.last_success ?? 0) > before) notify(t("vps.schedule.backedUp"));
    }, t("vps.schedule.error.run"), () => void backUpNow());

  const turnOff = () =>
    run("off", async () => {
      await api.disableVpsBackupSchedule(profile.id);
      updateVpsBackupSchedule(profile.id, null);
      notify(t("vps.schedule.turnedOff"));
    }, t("vps.schedule.error.off"), () => void turnOff());

  return (
    <DialogContent
      className="dialog-content remove-server-dialog vps-backup-schedule-dialog"
      heading={t("vps.schedule.title")}
      description={t("vps.schedule.description")}
      closeDisabled={busy}
      footerNote={busy ? null : blocker ?? (schedule && !disconnected ? t("vps.schedule.disconnected") : null)}
      footer={<>
        {schedule && <button className="text-button danger-text dialog-back" type="button" disabled={busy} onClick={() => void turnOff()}>
          {task === "off" ? <Busy label={t("vps.schedule.turningOff")} /> : t("vps.schedule.turnOff")}
        </button>}
        {schedule && <button className="secondary-button" type="button" disabled={busy || !disconnected} onClick={() => void backUpNow()}>
          {task === "run" ? <Busy label={t("vps.schedule.running")} /> : t("vps.schedule.runNow")}
        </button>}
        <button className="primary-button" type="submit" form={formId} disabled={busy || !valid}>
          {task === "save" ? <Busy label={t("vps.schedule.saving")} /> : t("vps.schedule.save")}
        </button>
      </>}
    >
      <form
        className="uninstall-form"
        id={formId}
        onSubmit={(event) => {
          event.preventDefault();
          if (valid) void save();
        }}
      >
        {error && <InlineError message={error.message} onRetry={error.retry} retryDisabled={busy} />}
        <fieldset disabled={busy} className="ssh-operation-fields">
          {schedule && (
            <div className="vps-backup-status" role="status">
              <p>
                {schedule.last_success
                  ? t("vps.schedule.lastBackup", { age: backupAge(schedule.last_success) })
                  : t("vps.schedule.noBackup")}
              </p>
              {schedule.last_failure && (
                <p className="vps-backup-failure">{t("vps.schedule.failed", { message: schedule.last_failure.message })}</p>
              )}
              {schedule.stale && !schedule.last_failure && <p>{t("vps.schedule.stale")}</p>}
            </div>
          )}
          {savedLogin === false && <p className="field-note">{t("vps.schedule.loginMissing")}</p>}
          <Field label={t("vps.schedule.folder")} hint={t("vps.schedule.folderHint")}>
            <div className="file-picker-row">
              <input className="mono" value={folder} readOnly placeholder={t("vps.common.noFile")} />
              <button className="secondary-button" type="button" onClick={() => void chooseFolder()}>
                {t("vps.schedule.chooseFolder")}
              </button>
            </div>
          </Field>
          <div className="field-grid two-column backup-schedule-fields">
            <Field label={t("vps.schedule.frequency")}>
              <select value={interval} onChange={(event) => setIntervalDays(Number(event.target.value))}>
                {intervals.map(([days, label]) => (
                  <option key={days} value={days}>
                    {t(label)}
                  </option>
                ))}
              </select>
            </Field>
            <Field label={t("vps.schedule.keep")} hint={t("vps.schedule.keepHint")} error={keep && !keepValid ? t("vps.schedule.keepHint") : undefined}>
              <input
                type="number"
                min={1}
                max={30}
                value={keep}
                onChange={(event) => setKeep(event.target.value)}
              />
            </Field>
          </div>
          <div className="field-grid two-column backup-passwords">
            <Field
              label={t("vps.common.backupPassword")}
              hint={t(schedule ? "vps.schedule.passwordKeepHint" : "vps.schedule.passwordHint")}
            >
              <SecretInput field="backup_password"
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                autoComplete="new-password"
              />
            </Field>
            <Field label={t("vps.backup.repeatPassword")}
              hint={password && passwordValid ? t("vps.common.passwordsMatch") : undefined}
              error={repeat && repeat !== password ? t("common.error.passwordsDiffer") : undefined}>
              <SecretInput field="backup_password"
                type="password"
                value={repeat}
                onChange={(event) => setRepeat(event.target.value)}
                autoComplete="new-password"
              />
            </Field>
          </div>
          {!schedule && <p className="field-note">{t("vps.schedule.disconnected")}</p>}
        </fieldset>
      </form>
    </DialogContent>
  );
}
