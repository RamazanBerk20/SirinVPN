import { DialogContent } from "../../components/DialogContent";
import * as Dialog from "@radix-ui/react-dialog";
import {
  ArrowClockwise,
  CaretRight,
  Check,
  Copy,
  DownloadSimple,
  GlobeHemisphereWest,
  Key,
  LockKey,
  ShieldCheck,
  Warning,
} from "@phosphor-icons/react";
import { useEffect, useState } from "react";
import { api } from "../../api";
import { type EndpointUpdateCodeResult, type ServerProfile } from "../../types";
import { Field, InlineError } from "../../components/ui";
import { errorMessage } from "../../lib/errors";

export function EndpointUpdateDialog({
  profile,
  open,
  onOpenChange,
  connected,
  onCompleted,
}: {
  profile: ServerProfile;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  connected: boolean;
  onCompleted: () => Promise<void>;
}) {
  const owner = profile.role === "owner";
  const [mode, setMode] = useState<"share" | "apply">(
    owner && profile.pending_previous_endpoint ? "share" : "apply",
  );
  const [update, setUpdate] = useState<EndpointUpdateCodeResult | null>(null);
  const [code, setCode] = useState("");
  const [busy, setBusy] = useState(false);
  const [published, setPublished] = useState(false);
  const [applied, setApplied] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) {
      setMode(owner && profile.pending_previous_endpoint ? "share" : "apply");
      setUpdate(null);
      setCode("");
      setBusy(false);
      setPublished(false);
      setApplied(false);
      setError(null);
    }
  }, [open, owner, profile.pending_previous_endpoint]);

  const changeOpen = (next: boolean) => {
    if (!next && busy) return;
    onOpenChange(next);
  };

  const createOrRetrieve = async () => {
    setBusy(true);
    setError(null);
    try {
      const result = await api.createEndpointUpdate(profile.id);
      setUpdate(result);
      setCode(result.code);
      await onCompleted();
    } catch (reason) {
      setError(
        errorMessage(
          reason,
          "The restored VPS could not create a signed endpoint update. Keep the old VPS running and retry while connected.",
        ),
      );
    } finally {
      setBusy(false);
    }
  };

  const checkCurrent = async () => {
    setBusy(true);
    setError(null);
    try {
      const result = await api.availableEndpointUpdate(profile.id);
      if (!result)
        throw new Error("This VPS has no published endpoint update.");
      setUpdate(result);
      setCode(result.code);
    } catch (reason) {
      setError(
        errorMessage(
          reason,
          "No signed endpoint update could be retrieved from this VPS.",
        ),
      );
    } finally {
      setBusy(false);
    }
  };

  const publish = async () => {
    if (!code.trim()) return;
    setBusy(true);
    setError(null);
    try {
      await api.publishEndpointUpdate(profile.id, code.trim());
      setPublished(true);
      await onCompleted();
    } catch (reason) {
      setError(
        errorMessage(
          reason,
          "The old VPS was left installed, but the endpoint update could not be published there.",
        ),
      );
    } finally {
      setBusy(false);
    }
  };

  const apply = async () => {
    if (!code.trim()) return;
    setBusy(true);
    setError(null);
    try {
      await api.applyEndpointUpdate(profile.id, code.trim());
      setApplied(true);
      await onCompleted();
    } catch (reason) {
      setError(
        errorMessage(
          reason,
          "The update could not be completed. Check the connection status and retry.",
        ),
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog.Root open={open} onOpenChange={changeOpen}>
      <Dialog.Portal>
        <Dialog.Overlay className="dialog-overlay" />
        <DialogContent className="dialog-content invitation-dialog endpoint-update-dialog"
          heading={<>{mode === "share"
              ? "Move devices to a new VPS address"
              : "Update this device endpoint"}</>}
          description={<>Signed updates verify this server’s identity and let devices catch up
            to its current addresses, ports, and transport settings.</>}
          closeDisabled={busy} closeLabel="Close">

          {owner ? (
            <div className="segmented-control endpoint-update-tabs">
              <button
                type="button"
                aria-pressed={mode === "share"}
                onClick={() => setMode("share")}
              >
                Share migration
              </button>
              <button
                type="button"
                aria-pressed={mode === "apply"}
                onClick={() => setMode("apply")}
              >
                Update this device
              </button>
            </div>
          ) : null}

          {mode === "share" ? (
            <div className="endpoint-update-flow">
              {profile.pending_previous_endpoint ? (
                <div className="warning-note replacement-warning">
                  <Warning size={18} weight="fill" />
                  <span>
                    Devices still using {profile.pending_previous_endpoint.host}{" "}
                    need a signed update before that VPS can be retired.
                  </span>
                </div>
              ) : null}
              {!update ? (
                <div className="endpoint-update-intro">
                  <GlobeHemisphereWest size={28} weight="duotone" />
                  <h3>
                    {profile.pending_previous_endpoint
                      ? "Create the migration handoff"
                      : "Retrieve the latest handoff"}
                  </h3>
                  <p>
                    Connect to the restored VPS. It signs the new endpoint
                    without exposing a private key or contacting a SirinVPN
                    cloud.
                  </p>
                  <button
                    className="primary-button"
                    disabled={!connected || busy}
                    onClick={() => void createOrRetrieve()}
                  >
                    {busy ? (
                      <ArrowClockwise className="spin" size={18} />
                    ) : (
                      <Key size={18} />
                    )}
                    {profile.pending_previous_endpoint
                      ? "Create signed update"
                      : "Retrieve signed update"}
                  </button>
                  {!connected ? (
                    <small>Connect to the current restored VPS first.</small>
                  ) : null}
                </div>
              ) : (
                <>
                  <div className="endpoint-transition-summary">
                    <code>
                      {endpointLabel(update.previous_endpoint)}
                    </code>
                    <CaretRight size={18} />
                    <code>
                      {endpointLabel(update.endpoint)}
                    </code>
                    <span>Generation {update.generation}</span>
                  </div>
                  <Field
                    label="Signed endpoint update"
                    hint="This code contains no access key. Its signature prevents modification."
                  >
                    <textarea
                      className="secret-code-output mono"
                      value={code}
                      readOnly
                      aria-label="Signed endpoint update code"
                    />
                  </Field>
                  <div className="dialog-actions">
                    <button
                      className="secondary-button"
                      onClick={() => void navigator.clipboard.writeText(code)}
                    >
                      <Copy size={17} /> Copy code
                    </button>
                    <button
                      className="primary-button"
                      disabled={busy || published}
                      onClick={() => void publish()}
                    >
                      {busy ? (
                        <ArrowClockwise className="spin" size={18} />
                      ) : (
                        <GlobeHemisphereWest size={18} />
                      )}
                      {published
                        ? "Published on old VPS"
                        : "Publish on old VPS"}
                    </button>
                  </div>
                  <p className="form-footnote">
                    <LockKey size={15} /> Publishing authenticates to the previous VPS
                    and stores its signed handoff. The old VPS then serves migration
                    control while VPN traffic moves to the new VPS.
                  </p>
                </>
              )}
              {error ? <InlineError message={error} /> : null}
            </div>
          ) : (
            <div className="endpoint-update-flow">
              {applied ? (
                <div className="backup-success endpoint-update-success">
                  <span>
                    <Check size={26} weight="bold" />
                  </span>
                  <h3>Endpoint updated</h3>
                  <p>
                    The server’s signed update was verified and saved. Check
                    the connection status for reachability at its new address.
                  </p>
                  <button
                    className="primary-button"
                    onClick={() => changeOpen(false)}
                  >
                    Done
                  </button>
                </div>
              ) : (
                <>
                  <p>
                    Paste the Owner’s signed code, or retrieve the current VPS’s
                    published handoff. An active session keeps its protection and routing settings.
                  </p>
                  <Field label="Signed endpoint update">
                    <textarea
                      className="secret-code-output mono"
                      value={code}
                      onChange={(event) => setCode(event.target.value)}
                      placeholder="sirm1.…"
                      spellCheck={false}
                    />
                  </Field>
                  {update ? (
                    <div className="endpoint-transition-summary">
                      <code>
                        {endpointLabel(update.previous_endpoint)}
                      </code>
                      <CaretRight size={18} />
                      <code>
                        {endpointLabel(update.endpoint)}
                      </code>
                      <span>Generation {update.generation}</span>
                    </div>
                  ) : null}
                  {error ? <InlineError message={error} /> : null}
                  <div className="dialog-actions">
                    <button
                      className="secondary-button"
                      disabled={!connected || busy}
                      onClick={() => void checkCurrent()}
                    >
                      <DownloadSimple size={17} /> Retrieve from current VPS
                    </button>
                    <button
                      className="primary-button"
                      disabled={!code.trim() || busy}
                      onClick={() => void apply()}
                    >
                      {busy ? (
                        <ArrowClockwise className="spin" size={18} />
                      ) : (
                        <ShieldCheck size={18} />
                      )}
                      Verify and switch
                    </button>
                  </div>
                  <p className="form-footnote">
                    <ShieldCheck size={15} /> Your device keys and pinned server
                    identity remain bound to this connection.
                  </p>
                </>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function endpointLabel(endpoint: { host: string; wireguard_port: number }) {
  return `${endpoint.host.includes(":") ? `[${endpoint.host}]` : endpoint.host}:${endpoint.wireguard_port}`;
}
