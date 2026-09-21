import { confirmAction } from "../../lib/confirmAction";
import { TransportSetupFields, newTransportDraft, transportDraftIsValid, transportSetupFromDraft } from "../settings/TransportSetupFields";
import { useSshLogin } from "../../hooks/useSshLogin";
import { SplitDnsFields, splitDnsDraftIsValid, withSplitDns } from "../dns/SplitDnsFields";
import { SshLoginFields } from "../settings/SshLoginFields";
import { SshVerificationGuide } from "../settings/SshVerificationGuide";
import {
  CaretRight,
  Check,
  Copy,
  Key,
  LockKey,
  ShieldCheck,
  TerminalWindow,
  Warning,
} from "@phosphor-icons/react";
import { useState } from "react";
import { api } from "../../api";
import { privateDnsDraftIsValid, privateDnsRecordsFromDraft } from "../../dns";
import { formatDnsPolicy, validateHost } from "../../format";
import { type NetworkPreflight, type ProvisionResult } from "../../types";
import { ServerNetworkPreflight } from "../settings/ServerNetworkPreflight";
import { Field, InlineError } from "../../components/ui";
import { errorMessage } from "../../lib/errors";
import {
  type DnsPolicyChoice,
  type DnsEndpointDraft,
  newDnsEndpointDrafts,
  dnsDraftIsValid,
  dnsUpstreamFromDraft,
  privateDnsRecordSummary,
  PrivateDnsRecordFields,
  DnsPolicyFields,
} from "../dns/DnsFields";

export function SetupFlow({
  onComplete,
  compact = false,
}: {
  onComplete: (result: ProvisionResult) => Promise<void>;
  compact?: boolean;
}) {
  const [step, setStep] = useState<
    "details" | "fingerprint" | "installing" | "success"
  >("details");
  const [name, setName] = useState("My VPS");
  const [host, setHost] = useState("");
  const login = useSshLogin(host);
  const [busy, setBusy] = useState(false);
  const [replaceExistingInstallation, setReplaceExistingInstallation] =
    useState(false);
  const [dnsChoice, setDnsChoice] = useState<DnsPolicyChoice>("recursive");
  const [dnsEndpoints, setDnsEndpoints] =
    useState<DnsEndpointDraft[]>(newDnsEndpointDrafts);
  const [privateDnsRecords, setPrivateDnsRecords] = useState("");
  const [splitDns, setSplitDns] = useState("");
  const [transport, setTransport] = useState(() => newTransportDraft());
  const [fingerprint, setFingerprint] = useState("");
  const [result, setResult] = useState<ProvisionResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [preflight, setPreflight] = useState<NetworkPreflight | null>(null);

  const valid =
    validateHost(host) &&
    name.trim().length > 0 &&
    login.valid &&
    transportDraftIsValid(transport) &&
    dnsDraftIsValid(dnsChoice, dnsEndpoints) &&
    splitDnsDraftIsValid(splitDns) &&
    privateDnsDraftIsValid(privateDnsRecords, true);

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
    if (!valid || busy) return;
    setError(null);
    setPreflight(null);
    setBusy(true);
    try {
      setFingerprint(await api.probeHostKey(host.trim(), Number(login.port)));
      setStep("fingerprint");
    } catch {
      setError(
        "The VPS could not be reached over SSH. Check the address, port, and network.",
      );
    } finally {
      setBusy(false);
    }
  };

  const inspectNetwork = async () => {
    if (busy) return;
    setBusy(true);
    setError(null);
    setPreflight(null);
    try {
      setPreflight(await api.inspectServerNetwork({
        ssh: { host: host.trim(), ...(await login.prepare(fingerprint)) },
        transport: transportSetupFromDraft(transport),
      }));
    } catch (reason) {
      setError(errorMessage(reason, "The network inspection could not be completed."));
    } finally { setBusy(false); }
  };

  const provision = async () => {
    if (
      replaceExistingInstallation &&
      !await confirmAction(
        "Replace the existing SirinVPN installation? All current SirinVPN devices, invitations, and recovery material for this VPS will be revoked. Other VPS services are preserved.",
      )
    )
      return;
    setStep("installing");
    setError(null);
    try {
      const provisioned = await api.provisionServer({
        name: name.trim(),
        host: host.trim(),
        ...(await login.prepare(fingerprint)),
        replace_existing_installation: replaceExistingInstallation,
        transport: transportSetupFromDraft(transport),
        dns_upstream: withSplitDns(
          dnsChoice === "dns_over_tls" || dnsChoice === "dns_over_https"
            ? dnsUpstreamFromDraft(dnsChoice, dnsEndpoints)
            : { mode: "recursive" }, splitDns),
        private_dns_records: privateDnsRecordsFromDraft(privateDnsRecords),
      });
      setResult(provisioned);
      login.clearSecrets();
      setStep("success");
    } catch (reason) {
      login.clearSecrets();
      setStep("details");
      setError(
        errorMessage(
          reason,
          "Installation stopped safely. Existing networking was preserved; correct the issue and retry.",
        ),
      );
    }
  };

  if (step === "installing") {
    return (
      <div className="install-state" aria-live="polite">
        <div className="install-orbit">
          <ShieldCheck size={32} weight="duotone" />
        </div>
        <h2>Securing your VPS</h2>
        <p>
          Compatibility, identity, networking, private DNS, and SSH safety are
          being verified as one transaction.
        </p>
        <div
          className="install-track"
          role="progressbar"
          aria-label="Installation is in progress"
        >
          <span className="active" />
          <span />
          <span />
          <span />
          <span />
        </div>
        <small>Do not close the app while the rollback guard is active.</small>
      </div>
    );
  }

  if (step === "success" && result) {
    return (
      <div className="success-state">
        <span className="success-icon">
          <Check size={28} weight="bold" />
        </span>
        <h2>Your VPN is ready.</h2>
        <p>
          {result.profile.name} was added locally with{" "}
          {formatDnsPolicy(result.dns_upstream).toLowerCase()} and{" "}
          {privateDnsRecordSummary(result.private_dns_records.length)}. The
          private owner identity remains only on this device.
        </p>
        {result.network_preflight && <ServerNetworkPreflight report={result.network_preflight} />}
        <button
          className="primary-button"
          onClick={() => void onComplete(result)}
        >
          Open server
        </button>
      </div>
    );
  }

  if (step === "fingerprint") {
    return (
      <div className="fingerprint-step">
        <button className="back-button" onClick={() => setStep("details")}>
          Back
        </button>
        <div className="fingerprint-heading">
          <Key size={28} weight="duotone" aria-hidden="true" />
          <h2>Verify this VPS</h2>
        </div>
        <p>
          Check this fingerprint using your hosting provider’s browser console.
        </p>
        <div className="fingerprint-value">
          <code>{fingerprint}</code>
          <button
            className="icon-button"
            aria-label="Copy fingerprint"
            onClick={() => void navigator.clipboard.writeText(fingerprint)}
          >
            <Copy size={17} />
          </button>
        </div>
        {!preflight && <SshVerificationGuide confirmation="button" />}
        <div className="warning-note">
          <Warning size={18} weight="fill" />
          <span>
            A mismatch can mean the server was replaced or the connection is
            being intercepted.
          </span>
        </div>
        {replaceExistingInstallation ? (
          <div className="warning-note replacement-warning">
            <Warning size={18} weight="fill" />
            <span>
              This rotates the SirinVPN owner and server identity. Existing
              SirinVPN devices and invitations will stop working; unrelated VPS
              services remain intact.
            </span>
          </div>
        ) : null}
        {preflight && <ServerNetworkPreflight report={preflight} />}
        {error && <InlineError message={error} />}
        <div className="fingerprint-actions">
          <button className={preflight ? "secondary-button" : "primary-button"} disabled={busy} onClick={() => void inspectNetwork()}>
            {busy ? "Inspecting VPS network…" : preflight ? "Check network again" : "Fingerprint matches — inspect network"}
          </button>
          {preflight && <button className="primary-button" disabled={busy || preflight.issues.some((issue) => issue.blocking)} onClick={() => void provision()}>
            {replaceExistingInstallation ? "Replace SirinVPN" : "Install SirinVPN"}
          </button>}
        </div>
      </div>
    );
  }

  return (
    <form
      className={`setup-form ${compact ? "compact" : ""}`}
      onSubmit={(event) => {
        event.preventDefault();
        void inspect();
      }}
    >
      <div className="form-heading">
        <span>
          <TerminalWindow size={20} />
        </span>
        <div>
          <h2>Connect your server</h2>
          <p>
            {login.usingSaved ? "This login is already saved in this device’s secure credential store. Its in-memory session copy is discarded after use." : login.remember ? "After successful SSH authentication, Remember login saves these credentials in this device’s secure credential store for future VPS actions." : "Credentials are used in memory for this SSH session, then discarded."}
          </p>
        </div>
      </div>
      <div className="field-grid">
        <Field label="Server name" hint="Only stored on this device">
          <input
            value={name}
            onChange={(event) => setName(event.target.value)}
            autoComplete="off"
          />
        </Field>
      </div>
      <Field label="IP address or hostname">
        <input
          disabled={busy}
          value={host}
          onChange={(event) => setHost(event.target.value)}
          placeholder="203.0.113.10"
          autoCapitalize="none"
          spellCheck={false}
        />
      </Field>
      <fieldset className="ssh-operation-fields" disabled={busy}>
        <SshLoginFields login={login} />
      </fieldset>
      <details className="setup-advanced">
        <summary>Advanced server configuration</summary>
        <div className="setup-advanced-content">
          <TransportSetupFields value={transport} onChange={setTransport} />
          <DnsPolicyFields
            choice={dnsChoice}
            endpoints={dnsEndpoints}
            allowPreserve={false}
            onChoiceChange={setDnsChoice}
            onEndpointChange={updateDnsEndpoint}
          />
          <PrivateDnsRecordFields

            choice="replace"
            value={privateDnsRecords}
            allowPreserve={false}
            onChoiceChange={() => undefined}
            onValueChange={setPrivateDnsRecords}
          />
          <SplitDnsFields value={splitDns} onChange={setSplitDns} />
          <label
            className={`replacement-option ${replaceExistingInstallation ? "selected" : ""}`}
          >
            <input
              type="checkbox"
              checked={replaceExistingInstallation}
              onChange={(event) =>
                setReplaceExistingInstallation(event.target.checked)
              }
            />
            <span>
              <strong>Replace existing SirinVPN installation</strong>
              <small>
                Use only when SSH access is valid but every Owner device or
                recovery backup is gone.
              </small>
            </span>
          </label>
        </div>
      </details>
      {error ? <InlineError message={error} /> : null}
      <button
        className="primary-button"
        type="submit"
        disabled={!valid || busy}
      >
        {busy ? "Checking VPS…" : "Verify VPS"}{" "}
        <CaretRight size={17} weight="bold" />
      </button>
      <p className="form-footnote">
        <LockKey size={15} /> Direct connection. No SirinVPN service is
        involved.
      </p>
    </form>
  );
}
