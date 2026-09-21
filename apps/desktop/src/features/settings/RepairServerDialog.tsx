import { TransportSetupFields, newTransportDraft, transportDraftIsValid, transportSetupFromDraft } from "./TransportSetupFields";
import { DnsChangeReview } from "../dns/DnsChangeReview";
import { useSshLogin } from "../../hooks/useSshLogin";
import { SshLoginFields } from "./SshLoginFields";
import { RepairSummary } from "./RepairSummary";
import { DialogContent } from "../../components/DialogContent";
import * as Dialog from "@radix-ui/react-dialog";
import {
  ArrowClockwise,
  GlobeHemisphereWest,
} from "@phosphor-icons/react";
import { useEffect, useId, useState } from "react";
import { api } from "../../api";
import {
  useSshHostTrust,
  type InspectedSshHost,
} from "../../hooks/useSshHostTrust";
import { SshHostVerification } from "./SshHostVerification";
import { privateDnsDraftIsValid, privateDnsRecordsFromDraft } from "../../dns";
import { type RepairResult, type ServerProfile } from "../../types";
import { SplitDnsFields, splitDnsDraftIsValid, withSplitDns } from "../dns/SplitDnsFields";
import { InlineError } from "../../components/ui";
import { errorMessage } from "../../lib/errors";
import {
  type DnsPolicyChoice,
  type PrivateDnsRecordChoice,
  type DnsEndpointDraft,
  newDnsEndpointDrafts,
  dnsDraftIsValid,
  dnsUpstreamFromDraft,
  PrivateDnsRecordFields,
  DnsPolicyFields,
} from "../dns/DnsFields";

export function RepairServerDialog({
  profile,
  open,
  onOpenChange,
  disconnected,
  onCompleted,
  onReturnHome,
  intent = "repair",
}: {
  profile: ServerProfile;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  disconnected: boolean;
  onCompleted: () => Promise<void>;
  onReturnHome?: () => void;
  intent?: "repair" | "dns";
}) {
  const formId = useId();
  const [step, setStep] = useState<
    "details" | "fingerprint" | "review" | "repairing" | "success"
  >("details");
  const login = useSshLogin(profile.endpoint.host, open);
  const { port } = login;
  const trust = useSshHostTrust(profile.endpoint.host, Number(port), open);
  const [confirmed, setConfirmed] = useState(false);
  const [dnsChoice, setDnsChoice] = useState<DnsPolicyChoice>("preserve");
  const [dnsEndpoints, setDnsEndpoints] =
    useState<DnsEndpointDraft[]>(newDnsEndpointDrafts);
  const [privateDnsChoice, setPrivateDnsChoice] =
    useState<PrivateDnsRecordChoice>("preserve");
  const [privateDnsRecords, setPrivateDnsRecords] = useState("");
  const [splitDns, setSplitDns] = useState("");
  const [transport, setTransport] = useState(() => newTransportDraft(profile));
  const [result, setResult] = useState<RepairResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const clearSecrets = () => {
    login.clearSecrets();
  };

  useEffect(() => {
    if (!open) {
      clearSecrets();
      setStep("details");
      trust.reset();
      setConfirmed(false);
      setDnsChoice("preserve");
      setDnsEndpoints(newDnsEndpointDrafts());
      setPrivateDnsChoice("preserve");
      setPrivateDnsRecords("");
      setSplitDns("");
      setTransport(newTransportDraft(profile));
      setResult(null);
      setError(null);
      setBusy(false);
    }
  }, [open]);

  const changeOpen = (next: boolean) => {
    if (!next && (busy || step === "repairing")) return;
    onOpenChange(next);
  };

  const sshValid =
    disconnected &&
    login.valid &&
    (intent === "dns" || transportDraftIsValid(transport)) &&
    dnsDraftIsValid(dnsChoice, dnsEndpoints) &&
    (dnsChoice === "preserve" || splitDnsDraftIsValid(splitDns)) &&
    (privateDnsChoice !== "replace" ||
      privateDnsDraftIsValid(privateDnsRecords, false));

  const updateDnsEndpoint = (
    index: number,
    field: keyof DnsEndpointDraft,
    value: string,
  ) => {
    setDnsEndpoints((current) =>
      current.map((endpoint, endpointIndex) =>
        endpointIndex === index ? { ...endpoint, [field]: value } : endpoint,
      ),
    );
  };

  const inspect = async () => {
    if (!sshValid) return;
    setBusy(true);
    setError(null);
    try {
      const checked = await trust.inspect();
      if (!checked) return;
      setConfirmed(false);
      if (checked.status === "trusted") {
        if (intent === "dns") setStep("review");
        else await repair(checked);
      } else {
        setStep("fingerprint");
      }
    } catch (reason) {
      setError(errorMessage(reason, "The VPS could not be reached over SSH."));
    } finally {
      setBusy(false);
    }
  };

  const repair = async (
    checked: InspectedSshHost | null = trust.inspection,
  ) => {
    if (!checked || !sshValid || (checked.status !== "trusted" && !confirmed))
      return;
    setStep("repairing");
    setBusy(true);
    setError(null);
    try {
      const fingerprint = await trust.accept(checked, confirmed);
      const repaired = await api.repairServer({
        server_id: profile.id,
        ...(await login.prepare(fingerprint)),
        confirmed: true,
        transport: intent === "dns" ? null : transportSetupFromDraft(transport, profile),
        dns_upstream:
          dnsChoice === "preserve"
            ? null
            : withSplitDns(dnsChoice === "dns_over_tls" || dnsChoice === "dns_over_https"
              ? dnsUpstreamFromDraft(dnsChoice, dnsEndpoints)
              : { mode: "recursive" }, splitDns),
        private_dns_records:
          privateDnsChoice === "preserve"
            ? null
            : privateDnsChoice === "clear"
              ? []
              : privateDnsRecordsFromDraft(privateDnsRecords),
      });
      clearSecrets();
      await onCompleted();
      setResult(repaired);
      setStep("success");
    } catch (reason) {
      clearSecrets();
      setConfirmed(false);
      setStep("details");
      setError(
        errorMessage(
          reason,
          "Repair stopped safely. Server/device identities and the local secret were not intentionally changed; interrupted VPS changes are protected by rollback.",
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
        <DialogContent className="dialog-content remove-server-dialog repair-server-dialog"
          heading={step === "repairing"
              ? intent === "dns" ? "Applying DNS configuration" : "Repairing SirinVPN"
              : step === "success" ? intent === "dns" ? "DNS configuration complete" : "Repair complete" : `${intent === "dns" ? "Configure DNS for" : "Repair"} ${profile.name}`}
          description={step === "success"
            ? "Repair finished. Your server and device identities and existing access were preserved."
            : step === "repairing"
              ? "The VPS is being repaired and checked. Keep SirinVPN open until this finishes."
              : intent === "dns" ? "Review the resolver, private records and split DNS changes for this VPS." : "Restore this VPS’s VPN software and settings while preserving server and device identities."}
          closeDisabled={busy || step === "repairing"}
          footer={step === "repairing" ? <p role="status">This operation cannot be interrupted from this dialog.</p>
            : step === "success" ? <button className="primary-button" type="button" onClick={() => { onOpenChange(false); onReturnHome?.(); }}>Return to Home</button>
            : <>
              <button className="secondary-button" type="button" disabled={busy} onClick={() => changeOpen(false)}>Cancel</button>
              {step === "details" ? <button className="primary-button" type="submit" form={formId} disabled={!sshValid || busy}>{busy ? "Checking VPS…" : intent === "dns" ? "Review DNS changes" : "Repair VPS"}</button>
                : <button className="primary-button" type="button" disabled={busy || step === "fingerprint" && !confirmed} onClick={() => { if (intent === "dns" && step === "fingerprint") setStep("review"); else void repair(); }}>{intent === "dns" ? step === "fingerprint" ? "Review DNS changes" : "Apply DNS configuration" : "Repair VPS"}</button>}
            </>}
        >

          {step === "details" ? (
            <form
              className="uninstall-form"
              id={formId}
              onSubmit={(event) => {
                event.preventDefault();
                void inspect();
              }}
            >
              <fieldset disabled={busy} className="ssh-operation-fields">
                <div className="uninstall-target">
                  <GlobeHemisphereWest size={16} />
                  <code>{profile.endpoint.host}</code>
                </div>
                {!disconnected ? (
                  <InlineError message="Disconnect every active SirinVPN tunnel before repairing this VPS." />
                ) : null}
                <SshLoginFields login={login} />
                {intent === "dns" && <p>Review resolver mode, upstreams, private records and split DNS zones below. Unchanged choices preserve the existing DNS policy. This verified SSH operation also reinstalls bundled VPS software and restarts services; all devices using this VPS may briefly disconnect. Addresses and transport ports retain their current values.</p>}
                {intent !== "dns" && <TransportSetupFields value={transport} onChange={setTransport} existing />}
                <DnsPolicyFields
                  choice={dnsChoice}
                  endpoints={dnsEndpoints}
                  allowPreserve
                  onChoiceChange={setDnsChoice}
                  onEndpointChange={updateDnsEndpoint}
                />
                <PrivateDnsRecordFields
                  choice={privateDnsChoice}
                  value={privateDnsRecords}
                  allowPreserve
                  onChoiceChange={setPrivateDnsChoice}
                  onValueChange={setPrivateDnsRecords}
                />
                {dnsChoice !== "preserve" && <SplitDnsFields value={splitDns} onChange={setSplitDns} />}
                <p className="settings-note">
                  The VPN will be briefly unavailable while the server component
                  is updated. Server and device identities are preserved.
                </p>
                {error ? <InlineError message={error} /> : null}
              </fieldset>
            </form>
          ) : null}

          {step === "fingerprint" && trust.inspection ? (
            <div className="uninstall-fingerprint repair-fingerprint">
              <button
                className="back-button"
                onClick={() => setStep("details")}
              >
                Back
              </button>
              <SshHostVerification
                inspection={trust.inspection}
                confirmed={confirmed}
                onConfirmed={setConfirmed}
              />
            </div>
          ) : null}

          {step === "review" && <>
            <button type="button" className="back-button" disabled={busy} onClick={() => setStep("details")}>Back to DNS settings</button>
            <p>{profile.name} · SSH {profile.endpoint.host}:{port}</p>
            <DnsChangeReview choice={dnsChoice} endpoints={dnsEndpoints} privateChoice={privateDnsChoice} records={privateDnsRecords} splitDns={splitDns} />
            {error && <InlineError message={error} />}
          </>}

          {step === "repairing" ? (
            <div className="uninstall-progress repair-progress">
              <ArrowClockwise className="spin" size={26} />
              <strong>Repairing and verifying the VPS</strong>
              <p>
                The VPN will be briefly unavailable. SirinVPN is checking the
                repaired configuration and service health before finishing.
              </p>
            </div>
          ) : null}

          {step === "success" && result ? (
            <RepairSummary profile={profile} result={result} dnsPreserved={dnsChoice === "preserve"} recordsPreserved={privateDnsChoice === "preserve"} />
          ) : null}
        </DialogContent>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
