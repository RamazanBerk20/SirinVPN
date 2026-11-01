import { CloudArrowUp, ShieldCheck } from "@phosphor-icons/react";
import { useEffect, useMemo, useState } from "react";
import { api } from "../../api";
import { SecretInput } from "../../components/SecretInput";
import { Field, InlineError } from "../../components/ui";
import { t } from "../../i18n";
import { confirmAction } from "../../lib/confirmAction";
import { errorMessage } from "../../lib/errors";
import { registerNavigationGuard } from "../../lib/navigationGuard";
import type { CreatedHetznerServer, HetznerAddresses, HetznerCatalog, ProvisionResult } from "../../types";
import { SetupFlow, type SetupStep } from "./SetupFlow";

type Phase = "plan" | "creating" | "waiting" | "failed" | "install" | "kept" | "deleted";

/** Types offered in a location, cheapest first; the first x86 type is the default. */
export function plansFor(catalog: HetznerCatalog, location: string) {
  const total = (type: HetznerCatalog["server_types"][number]) =>
    Number(type.prices.find(price => price.location === location)?.total_monthly);
  return catalog.server_types
    .filter(type => type.prices.some(price => price.location === location))
    .sort((a, b) => Number(a.architecture !== "x86") - Number(b.architecture !== "x86") || total(a) - total(b));
}

export function HetznerFlow({ onComplete, compact = false }: {
  onComplete: (result: ProvisionResult) => Promise<void>;
  compact?: boolean;
}) {
  const [token, setToken] = useState("");
  const [catalog, setCatalog] = useState<HetznerCatalog | null>(null);
  const [location, setLocation] = useState("");
  const [serverType, setServerType] = useState("");
  const [phase, setPhase] = useState<Phase>("plan");
  const [created, setCreated] = useState<CreatedHetznerServer | null>(null);
  const [addresses, setAddresses] = useState<HetznerAddresses | null>(null);
  const [setupStep, setSetupStep] = useState<SetupStep>("details");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const plans = useMemo(() => catalog ? plansFor(catalog, location) : [], [catalog, location]);
  const plan = plans.find(type => type.name === serverType);
  const price = plan?.prices.find(item => item.location === location);
  const locationName = catalog?.locations.find(item => item.name === location)?.city ?? location;
  const server = created?.server;
  // Until it is installed or deleted, the server bills the Owner: leaving needs a decision.
  const unresolved = server !== undefined && !["kept", "deleted"].includes(phase) && setupStep !== "success";
  useEffect(() => {
    if (!unresolved) return;
    return registerNavigationGuard(() => phase !== "creating" && phase !== "waiting" && setupStep !== "installing"
      && window.confirm(t("onboarding.hetzner.leaveWarning")));
  }, [unresolved, phase, setupStep]);

  const loadPlans = async () => {
    setBusy(true);
    setError("");
    try {
      const loaded = await api.hetznerCatalog(token);
      const first = loaded.locations[0]?.name ?? "";
      setCatalog(loaded);
      setLocation(first);
      setServerType(plansFor(loaded, first)[0]?.name ?? "");
    } catch (reason) {
      setError(errorMessage(reason, t("onboarding.hetzner.error.catalog")));
    } finally { setBusy(false); }
  };

  const chooseLocation = (next: string) => {
    setLocation(next);
    if (catalog && !plansFor(catalog, next).some(type => type.name === serverType)) setServerType(plansFor(catalog, next)[0]?.name ?? "");
  };

  const wait = async (target: CreatedHetznerServer) => {
    setPhase("waiting");
    setError("");
    try {
      setAddresses(await api.waitHetznerServer(token, target.server));
      setPhase("install");
    } catch (reason) {
      setError(errorMessage(reason, t("onboarding.hetzner.error.wait")));
      setPhase("failed");
    }
  };

  const create = async () => {
    if (!plan || !price || !catalog) return;
    if (!await confirmAction({
      title: t("onboarding.hetzner.confirm.title"),
      message: t("onboarding.hetzner.confirm.message", { type: plan.name, location: locationName, total: price.total_monthly, currency: catalog.currency }),
      confirm: t("onboarding.hetzner.confirm.confirm"),
    })) return;
    setPhase("creating");
    setError("");
    try {
      const result = await api.createHetznerServer(token, { location, server_type: plan.name, accepted_monthly_price: price.total_monthly });
      setCreated(result);
      await wait(result);
    } catch (reason) {
      setError(errorMessage(reason, t("onboarding.hetzner.error.create")));
      setPhase("plan");
    }
  };

  const remove = async () => {
    if (!server || !await confirmAction({
      title: t("onboarding.hetzner.deleteConfirm.title", { name: server.name }),
      message: t("onboarding.hetzner.deleteConfirm.message"),
      confirm: t("onboarding.hetzner.deleteConfirm.confirm"),
    })) return;
    setBusy(true);
    setError("");
    try {
      await api.deleteHetznerServer(token, server);
      setPhase("deleted");
    } catch (reason) {
      setError(errorMessage(reason, t("onboarding.hetzner.error.delete")));
    } finally { setBusy(false); }
  };

  const tokenField = <Field label={t("onboarding.hetzner.token")} hint={t("onboarding.hetzner.tokenHint")}>
    <SecretInput type="password" value={token} disabled={busy} autoComplete="off" spellCheck={false}
      aria-label={t("onboarding.hetzner.token")} onChange={event => setToken(event.target.value)} />
  </Field>;
  const deleteButton = <button type="button" className="secondary-button" disabled={busy} onClick={() => void remove()}>
    {busy ? t("onboarding.hetzner.deleting") : t("onboarding.hetzner.delete")}
  </button>;

  if (phase === "creating" || phase === "waiting") return <div className="install-state" aria-live="polite">
    <div className="install-orbit"><CloudArrowUp size={32} weight="duotone" /></div>
    <h2>{phase === "creating" ? t("onboarding.hetzner.creating") : t("onboarding.hetzner.waiting", { name: server?.name ?? "" })}</h2>
    <small>{t("onboarding.hetzner.waitingHint")}</small>
    {phase === "waiting" && <button type="button" className="secondary-button" onClick={() => void api.cancelHetznerWait()}>{t("onboarding.hetzner.cancel")}</button>}
  </div>;

  if (phase === "deleted" && server) return <div className="success-state">
    <p>{t("onboarding.hetzner.deleted", { name: server.name })}</p>
    <button type="button" className="primary-button" onClick={() => { setCreated(null); setAddresses(null); setSetupStep("details"); setPhase("plan"); }}>{t("onboarding.hetzner.startOver")}</button>
  </div>;

  if ((phase === "failed" || phase === "kept") && created && server) return <div className="setup-form">
    <h2>{t("onboarding.hetzner.failedTitle", { name: server.name })}</h2>
    {error && <InlineError message={error} />}
    <p>{phase === "kept" ? t("onboarding.hetzner.kept", { name: server.name, fingerprint: server.host_key_sha256 }) : t("onboarding.hetzner.failedSummary")}</p>
    {created.private_key_path && <p className="settings-note">{t("onboarding.hetzner.keyPath", { path: created.private_key_path })}</p>}
    {tokenField}
    <div className="fingerprint-actions">
      {deleteButton}
      <button type="button" className="secondary-button" disabled={busy} onClick={() => void wait(created)}>{t("onboarding.hetzner.waitAgain")}</button>
      {phase === "failed" && <button type="button" className="secondary-button" disabled={busy} onClick={() => setPhase("kept")}>{t("onboarding.hetzner.keep")}</button>}
    </div>
  </div>;

  if (phase === "install" && created && server && addresses) return <div className="hetzner-install">
    <SetupFlow compact={compact} onStepChange={setSetupStep}
      created={{ host: addresses.ipv4, host_key_sha256: server.host_key_sha256, private_key_path: created.private_key_path }}
      onComplete={async (result) => { setToken(""); await onComplete(result); }} />
    {(setupStep === "details" || setupStep === "fingerprint") && <div className="setup-form">
      <p className="settings-note">{t("onboarding.hetzner.created", { name: server.name, ipv4: addresses.ipv4 })}</p>
      {created.private_key_path && <p className="settings-note">{t("onboarding.hetzner.keyPath", { path: created.private_key_path })}</p>}
      {error && <InlineError message={error} />}
      {deleteButton}
    </div>}
  </div>;

  return <form className={`setup-form ${compact ? "compact" : ""}`} onSubmit={event => { event.preventDefault(); void (catalog ? create() : loadPlans()); }}>
    <div className="form-heading">
      <span><CloudArrowUp size={20} /></span>
      <div><h2>{t("onboarding.hetzner.title")}</h2><p>{t("onboarding.hetzner.summary")}</p></div>
    </div>
    {tokenField}
    {catalog && <>
      <Field label={t("onboarding.hetzner.location")}>
        <select value={location} disabled={busy} onChange={event => chooseLocation(event.target.value)}>
          {catalog.locations.map(item => <option key={item.name} value={item.name}>{`${item.city}, ${item.country} (${item.name})`}</option>)}
        </select>
      </Field>
      <Field label={t("onboarding.hetzner.serverType")}>
        <select value={serverType} disabled={busy} onChange={event => setServerType(event.target.value)}>
          {plans.map(type => <option key={type.name} value={type.name}>{t("onboarding.hetzner.typeOption", {
            name: type.name, architecture: type.architecture, cores: type.cores, memory: type.memory_gb, disk: type.disk_gb,
            price: type.prices.find(item => item.location === location)?.total_monthly ?? "", currency: catalog.currency,
          })}</option>)}
        </select>
      </Field>
      {price && <p className="settings-note" role="status"><ShieldCheck size={16} /> {price.ipv4_monthly
        ? t("onboarding.hetzner.price", { total: price.total_monthly, currency: catalog.currency, server: price.server_monthly, ipv4: price.ipv4_monthly })
        : t("onboarding.hetzner.priceNoIpv4", { total: price.total_monthly, currency: catalog.currency })}</p>}
    </>}
    {error && <InlineError message={error} />}
    <button className="primary-button" type="submit" disabled={busy || !token || (catalog !== null && !price)}>
      {busy ? t("onboarding.hetzner.loading") : catalog && price
        ? t("onboarding.hetzner.create", { total: price.total_monthly, currency: catalog.currency })
        : t("onboarding.hetzner.loadPlans")}
    </button>
  </form>;
}
