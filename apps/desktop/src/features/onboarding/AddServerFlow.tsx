import { useState } from "react";
import { type ServerProfile } from "../../types";
import { ImportBackupFlow } from "./ImportBackupFlow";
import { JoinFlow } from "./JoinFlow";
import { SetupFlow } from "./SetupFlow";
import { RecoverAccessFlow } from "./RecoverAccessFlow";
import { isAndroid } from "../../platform";
import * as Dialog from "@radix-ui/react-dialog";
import { DialogContent } from "../../components/DialogContent";
import { QrCode, Database, Key, Archive, CaretRight, ShieldCheck } from "@phosphor-icons/react";
import { confirmNavigation } from "../../lib/navigationGuard";
import { t } from "../../i18n";

const choices = [
  { id: "join", label: "onboarding.choice.join.title", hint: "onboarding.choice.join.summary", icon: QrCode },
  { id: "provision", label: "onboarding.choice.provision.title", hint: "onboarding.choice.provision.summary", icon: Database },
  { id: "backup", label: "onboarding.choice.backup.title", hint: "onboarding.choice.backup.summary", icon: Archive },
  { id: "recovery", label: "onboarding.choice.recovery.title", hint: "onboarding.choice.recovery.summary", icon: Key },
] as const;

export function AddServerFlow({
  onAdded,
  compact = false,
  initialMode,
}: {
  onAdded: (profile: ServerProfile) => Promise<void>;
  compact?: boolean;
  initialMode?: "provision" | "join" | "backup";
}) {
  const [mode, setMode] = useState<"provision" | "join" | "backup" | "recovery" | null>(
    initialMode ?? (isAndroid ? null : "provision"),
  );
  // Switching unmounts the current flow; an installation in progress blocks it.
  const choose = (next: NonNullable<typeof mode>) => { if (next !== mode && confirmNavigation()) setMode(next); };
  const flow = mode === "provision" ? <SetupFlow onComplete={(result) => onAdded(result.profile)} compact={compact} />
    : mode === "join" ? <JoinFlow onComplete={onAdded} compact={compact} />
    : mode === "recovery" ? <RecoverAccessFlow onComplete={onAdded} compact={compact} />
    : mode === "backup" ? <ImportBackupFlow onComplete={onAdded} compact={compact} /> : null;
  const current = choices.find(choice => choice.id === mode);
  if (isAndroid) return <div className="mobile-add-server">
    <div className="mobile-choice-list" aria-label={t("onboarding.choice.listLabel")}>
      {choices.map(({ id, label, hint, icon: Icon }) => <button key={id} className={`mobile-list-row ${id === "join" ? "invitation-choice" : ""}`} onClick={() => setMode(id)}>
        <span className="mobile-row-icon"><Icon size={24} /></span><span><strong>{t(label)}</strong><small>{t(hint)}</small></span><CaretRight size={18} />
      </button>)}
    </div>
    <p className="mobile-privacy"><ShieldCheck size={17} /> {t("onboarding.choice.privacy")}</p>
    <Dialog.Root open={mode !== null} onOpenChange={open => { if (!open && confirmNavigation()) setMode(null); }}>
      <Dialog.Portal><Dialog.Overlay className="dialog-overlay" />
        <DialogContent className="dialog-content mobile-enrollment" heading={current ? t(current.label) : undefined} aria-describedby={undefined} closeLabel={t("onboarding.choice.back")}>
          {flow}
        </DialogContent>
      </Dialog.Portal>
    </Dialog.Root>
  </div>;
  return (
    <div className="add-server-flow">
      <div
        className="segmented-control add-mode"
        aria-label={t("onboarding.choice.listLabel")}
      >
        <button
          type="button"
          aria-pressed={mode === "provision"}
          onClick={() => choose("provision")}
        >
          {t("onboarding.mode.provision")}
        </button>
        <button
          type="button"
          aria-pressed={mode === "join"}
          onClick={() => choose("join")}
        >
          {t("onboarding.mode.join")}
        </button>
        <button
          type="button"
          aria-pressed={mode === "backup"}
          onClick={() => choose("backup")}
        >
          {t("onboarding.mode.backup")}
        </button>
        <button type="button" aria-pressed={mode === "recovery"} onClick={() => choose("recovery")}>{t("onboarding.mode.recovery")}</button>
      </div>
      {flow}
    </div>
  );
}
