import * as Dialog from "@radix-ui/react-dialog";
import { useEffect, useState } from "react";
import { api } from "../../api";
import { DialogContent } from "../../components/DialogContent";
import { SecretInput } from "../../components/SecretInput";
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
        <DialogContent
          className="dialog-content remove-server-dialog vps-backup-schedule-dialog"
          heading={t("vps.schedule.title")}
          description={t("vps.schedule.description")}
          closeDisabled={busy}
        >
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
        </DialogContent>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

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
  const [folder, setFolder] = useState(schedule?.folder ?? "");
  const [keep, setKeep] = useState(String(schedule?.keep ?? 4));
  const [interval, setIntervalDays] = useState<number>(schedule?.interval_days ?? 7);
  const [password, setPassword] = useState("");
  const [repeat, setRepeat] = useState("");
  const [running, setRunning] = useState(false);
  const [savedLogin, setSavedLogin] = useState<boolean | null>(null);
  const [error, setError] = useState<string | null>(null);

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
  const passwordValid = password
    ? [...password].length >= 12 && password === repeat
    : Boolean(schedule) && !repeat;
  const valid =
    folder.length > 0 &&
    Number.isInteger(keepCount) &&
    keepCount >= 1 &&
    keepCount <= 30 &&
    passwordValid;

  const run = async (action: () => Promise<void>, fallback: string) => {
    setBusy(true);
    setError(null);
    try {
      await action();
    } catch (reason) {
      setError(errorMessage(reason, fallback));
    } finally {
      setBusy(false);
      setRunning(false);
    }
  };

  const chooseFolder = () =>
    run(async () => {
      const selected = await openDialog({
        directory: true,
        title: t("vps.schedule.folderDialogTitle"),
      });
      if (typeof selected === "string") setFolder(selected);
    }, t("vps.common.error.picker"));

  const save = () =>
    run(async () => {
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
    }, t("vps.schedule.error.save"));

  const backUpNow = () => {
    setRunning(true);
    return run(async () => {
      updateVpsBackupSchedule(
        profile.id,
        await api.runScheduledVpsBackup(profile.id, true),
      );
    }, t("vps.schedule.error.run"));
  };

  const turnOff = () =>
    run(async () => {
      await api.disableVpsBackupSchedule(profile.id);
      updateVpsBackupSchedule(profile.id, null);
    }, t("vps.schedule.error.off"));

  return (
    <form
      className="uninstall-form"
      onSubmit={(event) => {
        event.preventDefault();
        if (valid) void save();
      }}
    >
      <fieldset disabled={busy} className="ssh-operation-fields">
        {schedule && (
          <div className="vps-backup-status" role="status">
            <p>
              {schedule.last_success
                ? t("vps.schedule.lastBackup", { age: backupAge(schedule.last_success) })
                : t("vps.schedule.noBackup")}
            </p>
            {schedule.last_failure && (
              <p>{t("vps.schedule.failed", { message: schedule.last_failure.message })}</p>
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
          <Field label={t("vps.schedule.keep")} hint={t("vps.schedule.keepHint")}>
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
            <SecretInput
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              autoComplete="new-password"
            />
          </Field>
          <Field label={t("vps.backup.repeatPassword")} error={repeat && repeat !== password ? t("common.error.passwordsDiffer") : undefined}>
            <SecretInput
              type="password"
              value={repeat}
              onChange={(event) => setRepeat(event.target.value)}
              autoComplete="new-password"
            />
          </Field>
        </div>
        <p className="field-note">{t("vps.schedule.disconnected")}</p>
        {error && <InlineError message={error} />}
        <div className="dialog-actions">
          {schedule && (
            <>
              <button className="text-button" type="button" onClick={() => void turnOff()}>
                {t("vps.schedule.turnOff")}
              </button>
              <button
                className="secondary-button"
                type="button"
                disabled={!disconnected}
                onClick={() => void backUpNow()}
              >
                {running ? t("vps.schedule.running") : t("vps.schedule.runNow")}
              </button>
            </>
          )}
          <button className="primary-button" type="submit" disabled={!valid}>
            {t("vps.schedule.save")}
          </button>
        </div>
      </fieldset>
    </form>
  );
}
