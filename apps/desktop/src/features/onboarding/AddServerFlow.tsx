import { useState } from "react";
import { type ServerProfile } from "../../types";
import { ImportBackupFlow } from "./ImportBackupFlow";
import { JoinFlow } from "./JoinFlow";
import { SetupFlow, type SetupNext, type SetupStep } from "./SetupFlow";
import { HetznerFlow } from "./HetznerFlow";
import { RecoverAccessFlow } from "./RecoverAccessFlow";
import { isAndroid } from "../../platform";
import * as Dialog from "@radix-ui/react-dialog";
import { DialogContent } from "../../components/DialogContent";
import { QrCode, Database, Lifebuoy, Archive, ArrowLeft, CaretRight, ShieldCheck, CloudArrowUp } from "@phosphor-icons/react";
import { ListRow } from "../../components/ListRow";
import { SettingsDisclosure } from "../settings/SettingsParts";
import { confirmNavigation } from "../../lib/navigationGuard";
import { t } from "../../i18n";

const choices = [
  { id: "join", label: "onboarding.choice.join.title", hint: "onboarding.choice.join.summary", icon: QrCode },
  { id: "provision", label: "onboarding.choice.provision.title", hint: "onboarding.choice.provision.summary", icon: Database },
  { id: "backup", label: "onboarding.choice.backup.title", hint: "onboarding.choice.backup.summary", icon: Archive },
  { id: "recovery", label: "onboarding.choice.recovery.title", hint: "onboarding.choice.recovery.summary", icon: Lifebuoy },
  // Needs a paid Hetzner account and an API token, so it waits under Advanced.
  { id: "hetzner", label: "onboarding.choice.hetzner.title", hint: "onboarding.choice.hetzner.summary", icon: CloudArrowUp, advanced: true },
] as const;
type Mode = (typeof choices)[number]["id"];

export function AddServerFlow({
  onAdded,
  compact = false,
  initialMode,
}: {
  /** `next` asks the app to open a page for the new server, e.g. Keys & recovery after setup. */
  onAdded: (profile: ServerProfile, next?: SetupNext) => Promise<void>;
  compact?: boolean;
  initialMode?: "provision" | "join" | "backup";
}) {
  // Both layouts start on the described list of ways to add a server; a tray or restore request opens one directly.
  const [mode, setMode] = useState<Mode | null>(initialMode ?? null);
  // Switching unmounts the current flow; an installation in progress blocks it.
  const choose = (next: Mode | null) => { if (next !== mode && confirmNavigation()) setMode(next); };
  // Past its first step the setup flow (also inside Hetzner) has its own Back; a second link to the options would compete with it.
  const [setupStep, setSetupStep] = useState<SetupStep>("details");
  const flow = mode === "provision" ? <SetupFlow onComplete={(result, next) => onAdded(result.profile, next)} compact={compact} onStepChange={setSetupStep} />
    : mode === "hetzner" ? <HetznerFlow onComplete={(result, next) => onAdded(result.profile, next)} onDone={() => choose(null)} onStepChange={setSetupStep} compact={compact} />
    : mode === "join" ? <JoinFlow onComplete={onAdded} compact={compact} />
    : mode === "recovery" ? <RecoverAccessFlow onComplete={onAdded} compact={compact} />
    : mode === "backup" ? <ImportBackupFlow onComplete={onAdded} compact={compact} /> : null;
  const current = choices.find(choice => choice.id === mode);
  const rows = (advanced: boolean) => choices.filter((choice) => ("advanced" in choice) === advanced).map(({ id, label, hint, icon: Icon }) =>
    <ListRow key={id} className={id === "join" ? "invitation-choice" : ""}
      icon={<Icon size={24} />} title={t(label)} subtitle={t(hint)} trailing={<CaretRight size={18} />} onClick={() => choose(id)} />);
  const list = <>
    <div className="mobile-choice-list" role="group" aria-label={t("onboarding.choice.listLabel")}>{rows(false)}</div>
    <SettingsDisclosure className="add-server-advanced" summary={t("onboarding.choice.advanced")}>
      <div className="mobile-choice-list">{rows(true)}</div>
    </SettingsDisclosure>
  </>;
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
      {(mode !== "provision" && mode !== "hetzner" || setupStep === "details") && <button type="button" className="text-button flow-back" onClick={() => choose(null)}><ArrowLeft size={16} aria-hidden="true" /> {t("onboarding.choice.back")}</button>}
      {flow}
    </> : list}
  </div>;
}
