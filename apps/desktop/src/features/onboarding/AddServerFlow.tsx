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

const choices = [
  { id: "join", label: "Use an invitation", hint: "Scan a QR code or enter your code", icon: QrCode },
  { id: "provision", label: "Set up my VPS", hint: "Create a VPN on your own server", icon: Database },
  { id: "backup", label: "Restore a backup", hint: "Import an encrypted device backup", icon: Archive },
  { id: "recovery", label: "Use a recovery key", hint: "Recover access to your server", icon: Key },
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
  const flow = mode === "provision" ? <SetupFlow onComplete={(result) => onAdded(result.profile)} compact={compact} />
    : mode === "join" ? <JoinFlow onComplete={onAdded} compact={compact} />
    : mode === "recovery" ? <RecoverAccessFlow onComplete={onAdded} compact={compact} />
    : mode === "backup" ? <ImportBackupFlow onComplete={onAdded} compact={compact} /> : null;
  if (isAndroid) return <div className="mobile-add-server">
    <div className="mobile-choice-list" aria-label="How to add a server">
      {choices.map(({ id, label, hint, icon: Icon }) => <button key={id} className={`mobile-list-row ${id === "join" ? "invitation-choice" : ""}`} onClick={() => setMode(id)}>
        <span className="mobile-row-icon"><Icon size={24} /></span><span><strong>{label}</strong><small>{hint}</small></span><CaretRight size={18} />
      </button>)}
    </div>
    <p className="mobile-privacy"><ShieldCheck size={17} /> No account. No telemetry.</p>
    <Dialog.Root open={mode !== null} onOpenChange={open => { if (!open && confirmNavigation()) setMode(null); }}>
      <Dialog.Portal><Dialog.Overlay className="dialog-overlay" />
        <DialogContent className="dialog-content mobile-enrollment" heading={choices.find(choice => choice.id === mode)?.label} aria-describedby={undefined} closeLabel="Back to connection options">
          {flow}
        </DialogContent>
      </Dialog.Portal>
    </Dialog.Root>
  </div>;
  return (
    <div className="add-server-flow">
      <div
        className="segmented-control add-mode"
        aria-label="How to add a server"
      >
        <button
          type="button"
          aria-pressed={mode === "provision"}
          onClick={() => setMode("provision")}
        >
          My VPS
        </button>
        <button
          type="button"
          aria-pressed={mode === "join"}
          onClick={() => setMode("join")}
        >
          Invitation
        </button>
        <button
          type="button"
          aria-pressed={mode === "backup"}
          onClick={() => setMode("backup")}
        >
          Backup
        </button>
        <button type="button" aria-pressed={mode === "recovery"} onClick={() => setMode("recovery")}>Recovery key</button>
      </div>
      {flow}
    </div>
  );
}
