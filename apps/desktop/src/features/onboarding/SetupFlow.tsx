import { confirmAction } from "../../lib/confirmAction";
import { TransportSetupFields, newTransportDraft, transportDraftIsValid, transportSetupFromDraft } from "../settings/TransportSetupFields";
import { useSshLogin } from "../../hooks/useSshLogin";
import { SplitDnsFields, splitDnsDraftIsValid, withSplitDns } from "../dns/SplitDnsFields";
import { SshLoginFields } from "../settings/SshLoginFields";
import { SshVerificationGuide } from "../settings/SshVerificationGuide";
import {
  CaretRight,
  Check,
  Key,
  ShieldCheck,
  TerminalWindow,
  Warning,
} from "@phosphor-icons/react";
import { useEffect, useRef, useState } from "react";
import { api } from "../../api";
import { privateDnsDraftIsValid, privateDnsRecordsFromDraft } from "../../dns";
import { validateHost } from "../../format";
import { type NetworkPreflight, type ProvisionResult } from "../../types";
import { ServerNetworkPreflight } from "../settings/ServerNetworkPreflight";
import { Field, InlineError } from "../../components/ui";
import { CopyButton } from "../../components/CopyButton";
import { errorMessage } from "../../lib/errors";
import { registerNavigationGuard } from "../../lib/navigationGuard";
import { t } from "../../i18n";
import {
  type DnsPolicyChoice,
  type DnsEndpointDraft,
  newDnsEndpointDrafts,
  dnsDraftIsValid,
  dnsUpstreamFromDraft,
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
  const [name, setName] = useState(() => t("onboarding.setup.defaultName"));
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
  // The backend saves the profile once provisioning succeeds. Until "Open
  // server" hands it to the app, report it on unmount so it is never lost.
  const unopened = useRef<ProvisionResult | null>(null);
  const mounted = useRef(false);
  const complete = useRef(onComplete);
  complete.current = onComplete;
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      const pending = unopened.current;
      unopened.current = null;
      if (pending) void complete.current(pending);
    };
  }, []);
  useEffect(() => step === "installing" ? registerNavigationGuard(() => false) : undefined, [step]);

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
      setError(t("onboarding.setup.error.unreachable"));
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
      setError(errorMessage(reason, t("onboarding.setup.error.network")));
    } finally { setBusy(false); }
  };

  const provision = async () => {
    if (
      replaceExistingInstallation &&
      !await confirmAction({
        title: t("onboarding.setup.confirmReplace.title"),
        message: t("onboarding.setup.confirmReplace.message"),
        confirm: t("onboarding.setup.confirmReplace.confirm"),
      })
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
      login.clearSecrets();
      if (!mounted.current) {
        void complete.current(provisioned);
        return;
      }
      unopened.current = provisioned;
      setResult(provisioned);
      setStep("success");
    } catch (reason) {
      login.clearSecrets();
      setStep("details");
      setError(errorMessage(reason, t("onboarding.setup.error.install")));
    }
  };

  if (step === "installing") {
    return (
      <div className="install-state" aria-live="polite">
        <div className="install-orbit">
          <ShieldCheck size={32} weight="duotone" />
        </div>
        <h2>{t("onboarding.setup.installing.title")}</h2>
        <div
          className="install-track"
          role="progressbar"
          aria-label={t("onboarding.setup.installing.progress")}
        >
          <span className="active" />
          <span />
          <span />
          <span />
          <span />
        </div>
        <small>{t("onboarding.setup.installing.keepOpen")}</small>
      </div>
    );
  }

  if (step === "success" && result) {
    return (
      <div className="success-state">
        <span className="success-icon">
          <Check size={28} weight="bold" />
        </span>
        <h2>{t("onboarding.setup.success.title")}</h2>
        <p>{t("onboarding.setup.success.summary", { name: result.profile.name })}</p>
        {result.network_preflight && <ServerNetworkPreflight report={result.network_preflight} />}
        <button
          className="primary-button"
          onClick={() => {
            unopened.current = null;
            void onComplete(result);
          }}
        >
          {t("onboarding.setup.success.open")}
        </button>
      </div>
    );
  }

  if (step === "fingerprint") {
    return (
      <div className="fingerprint-step">
        <button className="back-button" onClick={() => setStep("details")}>
          {t("common.action.back")}
        </button>
        <div className="fingerprint-heading">
          <Key size={28} weight="duotone" aria-hidden="true" />
          <h2>{t("onboarding.setup.fingerprint.title")}</h2>
        </div>
        <p>{t("onboarding.setup.fingerprint.summary")}</p>
        <div className="fingerprint-value">
          <code>{fingerprint}</code>
          <CopyButton value={fingerprint} label={t("onboarding.setup.fingerprint.copy")} />
        </div>
        {!preflight && <SshVerificationGuide confirmation="button" />}
        <div className="warning-note">
          <Warning size={18} weight="fill" />
          <span>{t("onboarding.setup.fingerprint.mismatch")}</span>
        </div>
        {replaceExistingInstallation ? (
          <div className="warning-note replacement-warning">
            <Warning size={18} weight="fill" />
            <span>{t("onboarding.setup.fingerprint.replaceWarning")}</span>
          </div>
        ) : null}
        {preflight && <ServerNetworkPreflight report={preflight} />}
        {error && <InlineError message={error} />}
        <div className="fingerprint-actions">
          <button className={preflight ? "secondary-button" : "primary-button"} disabled={busy} onClick={() => void inspectNetwork()}>
            {busy ? t("onboarding.setup.fingerprint.checking") : preflight ? t("onboarding.setup.fingerprint.checkAgain") : t("onboarding.setup.fingerprint.matches")}
          </button>
          {preflight && <button className="primary-button" disabled={busy || preflight.issues.some((issue) => issue.blocking)} onClick={() => void provision()}>
            {replaceExistingInstallation ? t("onboarding.setup.fingerprint.replace") : t("onboarding.setup.fingerprint.install")}
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
          <h2>{t("onboarding.setup.title")}</h2>
          <p>{t("onboarding.setup.summary")}</p>
        </div>
      </div>
      <div className="field-grid">
        <Field label={t("onboarding.setup.name")} hint={t("onboarding.setup.nameHint")}>
          <input
            value={name}
            onChange={(event) => setName(event.target.value)}
            autoComplete="off"
          />
        </Field>
      </div>
      <Field label={t("onboarding.setup.host")}>
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
        <summary>{t("onboarding.setup.advanced")}</summary>
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
              <strong>{t("onboarding.setup.replace.title")}</strong>
              <small>{t("onboarding.setup.replace.summary")}</small>
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
        {busy ? t("onboarding.setup.verifying") : t("onboarding.setup.verify")}{" "}
        <CaretRight size={17} weight="bold" />
      </button>
    </form>
  );
}
