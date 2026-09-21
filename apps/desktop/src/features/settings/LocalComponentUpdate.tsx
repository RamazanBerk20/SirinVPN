import * as Dialog from "@radix-ui/react-dialog";
import { DialogContent } from "../../components/DialogContent";
import { useEffect, useState } from "react";
import { api } from "../../api";
import { InlineError } from "../../components/ui";
import { errorMessage } from "../../lib/errors";

export function LocalComponentUpdate({
  open,
  onOpenChange,
  onCheckUpdates,
  disconnected,
  onUpdated,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onCheckUpdates: () => void;
  disconnected: boolean;
  onUpdated: () => Promise<void>;
}) {
  const [status, setStatus] = useState<{ install_available: boolean; update_required: boolean } | null>(null);
  const [loading, setLoading] = useState(false);
  const [installing, setInstalling] = useState(false);
  const [error, setError] = useState("");
  const [updated, setUpdated] = useState(false);
  useEffect(() => {
    if (!open) return;
    let active = true;
    setStatus(null); setError(""); setUpdated(false); setLoading(true);
    api.localComponentUpdateStatus().then((value) => {
      if (active) setStatus(value);
    }).catch((reason) => {
      if (active) setError(errorMessage(reason, "The local VPN component could not be checked."));
    }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [open]);
  async function install() {
    if (installing || !disconnected || !status?.install_available) return;
    setInstalling(true); setError("");
    try {
      await api.installLocalVpnComponent();
      setStatus({ install_available: true, update_required: false });
      setUpdated(true);
      await onUpdated();
    } catch (reason) {
      setError(errorMessage(reason, "The local VPN component was not updated. Complete the administrator prompt and try again."));
    } finally { setInstalling(false); }
  }
  return (
    <Dialog.Root open={open} onOpenChange={(next) => { if (!installing) onOpenChange(next); }}>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <DialogContent className="dialog-content"
          heading={<>Update the local VPN component</>}
          description={<>Update this computer's VPN component to support the app's current
            connection controls and session measurements.</>}
          closeDisabled={installing} closeLabel="Close component update">
          {loading && <p className="settings-note" role="status">Checking the bundled VPN component…</p>}
          {status?.install_available ? <>
            <p className="settings-note">
              This app already includes the matching VPN component. Install it on
              this computer using the normal administrator prompt.
            </p>
            <p className="settings-note">
              Updating VPS software or replacing an AppImage does not update the
              system component. This step uses the files bundled with this app.
            </p>
            {!status.update_required && <p role="status">{updated ? "The local VPN component is updated. You can connect from Home." : "The local VPN component is already current."}</p>}
            {status.update_required && <>
              {!disconnected && <p className="settings-note">Disconnect and release VPN protection before updating this component.</p>}
              <button className="primary-button" disabled={installing || !disconnected} onClick={() => void install()}>
                {installing ? "Waiting for administrator approval…" : "Update local VPN component"}
              </button>
            </>}
          </> : status && <>
          <ol className="maintenance-plan">
            <li>
              Install the current SirinVPN package for this computer, which includes its
              VPN service, or review an authenticated app update below.
            </li>
            <li>
              Review the update screen's connection requirements before
              approving installation.
            </li>
            <li>
              Reopen SirinVPN and connect again. Supported tray controls become
              available after the component update; live rates need two readings.
            </li>
          </ol>
          <p className="settings-note">
            Updating VPS software does not update the helper on this computer.
            The app update screen requires a release source you trust.
          </p>
          <button
            className="primary-button"
            onClick={() => {
              onOpenChange(false);
              onCheckUpdates();
            }}
          >
            Review app update
          </button>
          </>}
          <InlineError message={error} />
        </DialogContent>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
