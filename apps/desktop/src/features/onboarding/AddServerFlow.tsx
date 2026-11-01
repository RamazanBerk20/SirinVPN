import { useState } from "react";
import { type ServerProfile } from "../../types";
import { ImportBackupFlow } from "./ImportBackupFlow";
import { JoinFlow } from "./JoinFlow";
import { SetupFlow, type SetupStep } from "./SetupFlow";
import { HetznerFlow } from "./HetznerFlow";
import { RecoverAccessFlow } from "./RecoverAccessFlow";
import { isAndroid } from "../../platform";
import * as Dialog from "@radix-ui/react-dialog";
import { DialogContent } from "../../components/DialogContent";
import { QrCode, Database, Key, Archive, ArrowLeft, CaretRight, ShieldCheck, CloudArrowUp } from "@phosphor-icons/react";
import { ListRow } from "../../components/ListRow";
import { confirmNavigation } from "../../lib/navigationGuard";
import { t } from "../../i18n";

const choices = [
  { id: "join", label: "onboarding.choice.join.title", hint: "onboarding.choice.join.summary", icon: QrCode },
  { id: "provision", label: "onboarding.choice.provision.title", hint: "onboarding.choice.provision.summary", icon: Database },
  { id: "hetzner", label: "onboarding.choice.hetzner.title", hint: "onboarding.choice.hetzner.summary", icon: CloudArrowUp },
  { id: "backup", label: "onboarding.choice.backup.title", hint: "onboarding.choice.backup.summary", icon: Archive },
  { id: "recovery", label: "onboarding.choice.recovery.title", hint: "onboarding.choice.recovery.summary", icon: Key },
] as const;
type Mode = (typeof choices)[number]["id"];

export function AddServerFlow({
  onAdded,
  compact = false,
  initialMode,
}: {
  onAdded: (profile: ServerProfile) => Promise<void>;
  compact?: boolean;
  initialMode?: "provision" | "join" | "backup";
}) {
  // Both layouts start on the described list of ways to add a server; a tray or restore request opens one directly.
  const [mode, setMode] = useState<Mode | null>(initialMode ?? null);
  // Switching unmounts the current flow; an installation in progress blocks it.
  const choose = (next: Mode | null) => { if (next !== mode && confirmNavigation()) setMode(next); };
  // Past its first step the setup flow has its own Back; a second link to the options would compete with it.
  const [setupStep, setSetupStep] = useState<SetupStep>("details");
  const flow = mode === "provision" ? <SetupFlow onComplete={(result) => onAdded(result.profile)} compact={compact} onStepChange={setSetupStep} />
    : mode === "hetzner" ? <HetznerFlow onComplete={(result) => onAdded(result.profile)} compact={compact} />
    : mode === "join" ? <JoinFlow onComplete={onAdded} compact={compact} />
    : mode === "recovery" ? <RecoverAccessFlow onComplete={onAdded} compact={compact} />
    : mode === "backup" ? <ImportBackupFlow onComplete={onAdded} compact={compact} /> : null;
  const current = choices.find(choice => choice.id === mode);
  const list = <div className="mobile-choice-list" role="group" aria-label={t("onboarding.choice.listLabel")}>
    {choices.map(({ id, label, hint, icon: Icon }) => <ListRow key={id} className={id === "join" ? "invitation-choice" : ""}
      icon={<Icon size={24} />} title={t(label)} subtitle={t(hint)} trailing={<CaretRight size={18} />} onClick={() => choose(id)} />)}
  </div>;
  if (isAndroid) return <div className="mobile-add-server">
    {list}
    <p className="mobile-privacy"><ShieldCheck size={17} /> {t("onboarding.choice.privacy")}</p>
    <Dialog.Root open={mode !== null} onOpenChange={open => { if (!open && confirmNavigation()) setMode(null); }}>
      <Dialog.Portal><Dialog.Overlay className="dialog-overlay" />
        <DialogContent className="dialog-content mobile-enrollment" heading={current ? t(current.label) : undefined} aria-describedby={undefined} closeLabel={t("onboarding.choice.back")}>
          {flow}
        </DialogContent>
      </Dialog.Portal>
    </Dialog.Root>
  </div>;
  return <div className="add-server-flow">
    {current ? <>
      {(mode !== "provision" || setupStep === "details") && <button type="button" className="text-button add-server-back" onClick={() => choose(null)}><ArrowLeft size={16} /> {t("onboarding.choice.back")}</button>}
      {flow}
    </> : list}
  </div>;
}
