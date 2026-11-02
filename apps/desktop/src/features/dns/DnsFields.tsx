import { dnsEndpointAddressIsUsable, dnsOverHttpsPathIsValid, privateDnsDraftIsValid } from "../../dns";
import { validateHost } from "../../format";
import { type DnsUpstream } from "../../types";
import { Field } from "../../components/ui";
import { formatNumber, t } from "../../i18n";

export type DnsPolicyChoice =
  "preserve" | "recursive" | "dns_over_tls" | "dns_over_https";

export type PrivateDnsRecordChoice = "preserve" | "replace" | "clear";

export type Nat64Choice = "preserve" | "replace" | "clear";

/** An IPv6 network written with or without its `/96`; the VPS checks the rest. */
export function nat64PrefixIsValid(value: string): boolean {
  const address = value.trim().replace(/\/96$/, "");
  return address.includes(":") && validateHost(address);
}

const defaultDohPath = "/dns-query";

export interface DnsEndpointDraft {
  address: string;
  authenticationName: string;
  path: string;
}

export function newDnsEndpointDrafts(): DnsEndpointDraft[] {
  return [
    { address: "", authenticationName: "", path: defaultDohPath },
    { address: "", authenticationName: "", path: defaultDohPath },
  ];
}

function endpointKey(choice: DnsPolicyChoice, endpoint: DnsEndpointDraft) {
  return [endpoint.address.trim().toLowerCase(), endpoint.authenticationName.trim().toLowerCase(), choice === "dns_over_https" ? endpoint.path.trim() : ""].join("#");
}

function tlsNameIsValid(value: string) {
  // TLS names are DNS names; the VPS rejects IPv6 literals here.
  return validateHost(value) && !value.includes(":") && !value.trim().endsWith(".");
}

/** The first field-level problem in each part of a resolver, once the user has started filling it. */
function endpointErrors(choice: DnsPolicyChoice, endpoints: DnsEndpointDraft[], index: number) {
  const endpoint = endpoints[index];
  if (!endpoint.address.trim() && !endpoint.authenticationName.trim()) return {};
  const duplicate = index > 0 && endpointKey(choice, endpoint) === endpointKey(choice, endpoints[0]);
  return {
    address: !dnsEndpointAddressIsUsable(endpoint.address) ? t("dns.resolver.error.address") : duplicate ? t("dns.resolver.error.duplicate") : undefined,
    name: !tlsNameIsValid(endpoint.authenticationName) ? t("dns.resolver.error.name") : undefined,
    path: choice === "dns_over_https" && !dnsOverHttpsPathIsValid(endpoint.path) ? t("dns.resolver.error.path") : undefined,
  };
}

/** Names the first invalid record line, or the limit when there are too many. */
export function privateDnsError(value: string): string | undefined {
  if (privateDnsDraftIsValid(value, true)) return undefined;
  const line = value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean).find((item) => !privateDnsDraftIsValid(item, true));
  return line ? t("dns.records.invalidLine", { line }) : t("dns.records.invalid");
}

export function dnsDraftIsValid(
  choice: DnsPolicyChoice,
  endpoints: DnsEndpointDraft[],
): boolean {
  if (choice !== "dns_over_tls" && choice !== "dns_over_https") return true;
  const populated = endpoints.filter(
    (endpoint) => endpoint.address.trim() || endpoint.authenticationName.trim(),
  );
  const normalized = populated.map((endpoint) => endpointKey(choice, endpoint));
  return (
    populated.length > 0 &&
    populated.every(
      (endpoint) =>
        dnsEndpointAddressIsUsable(endpoint.address) &&
        tlsNameIsValid(endpoint.authenticationName) &&
        (choice !== "dns_over_https" || dnsOverHttpsPathIsValid(endpoint.path)),
    ) &&
    new Set(normalized).size === normalized.length
  );
}

export function dnsUpstreamFromDraft(
  choice: "dns_over_tls" | "dns_over_https",
  endpoints: DnsEndpointDraft[],
): DnsUpstream {
  const populated = endpoints.filter(
    (endpoint) => endpoint.address.trim() || endpoint.authenticationName.trim(),
  );
  if (choice === "dns_over_https") {
    return {
      mode: "dns_over_https",
      endpoints: populated.map((endpoint) => ({
        address: endpoint.address.trim(),
        authentication_name: endpoint.authenticationName.trim().toLowerCase(),
        path: endpoint.path.trim(),
      })),
    };
  }
  return {
    mode: "dns_over_tls",
    endpoints: populated.map((endpoint) => ({
      address: endpoint.address.trim(),
      authentication_name: endpoint.authenticationName.trim().toLowerCase(),
    })),
  };
}

export function PrivateDnsRecordFields({
  choice,
  value,
  allowPreserve,
  onChoiceChange,
  onValueChange,
}: {
  choice: PrivateDnsRecordChoice;
  value: string;
  allowPreserve: boolean;
  onChoiceChange: (choice: PrivateDnsRecordChoice) => void;
  onValueChange: (value: string) => void;
}) {
  return (
    <fieldset className="auth-method dns-policy private-dns-policy">
      <legend>{t("dns.records.legend")}</legend>
      {allowPreserve ? (
        <div className="segmented-control dns-segmented with-preserve">
          <button
            type="button"
            aria-pressed={choice === "preserve"}
            onClick={() => onChoiceChange("preserve")}
          >
            {t("dns.records.mode.preserve")}
          </button>
          <button
            type="button"
            aria-pressed={choice === "replace"}
            onClick={() => onChoiceChange("replace")}
          >
            {t("dns.records.mode.replace")}
          </button>
          <button
            type="button"
            className="danger-choice"
            aria-pressed={choice === "clear"}
            onClick={() => onChoiceChange("clear")}
          >
            {t("dns.records.mode.clear")}
          </button>
        </div>
      ) : null}
      {choice === "clear"
        ? <p className="dns-policy-note danger-note">{t("dns.records.note.clear")}</p>
        : <p className="dns-policy-note">{t(choice === "preserve" ? "dns.records.note.preserve" : "dns.records.note.replace")}</p>}
      {choice === "replace" ? (
        <Field label={t("dns.records.label")} hint={t("dns.records.hint")} error={privateDnsError(value)}>
          <textarea
            className="private-dns-record-input mono"
            value={value}
            onChange={(event) => onValueChange(event.target.value)}
            placeholder={t("dns.example", { value: "nas.home=10.20.30.40" })}
            autoCapitalize="none"
            autoComplete="off"
            spellCheck={false}
          />
        </Field>
      ) : null}
    </fieldset>
  );
}

export function Nat64Fields({
  choice,
  value,
  allowPreserve,
  onChoiceChange,
  onValueChange,
}: {
  choice: Nat64Choice;
  value: string;
  allowPreserve: boolean;
  onChoiceChange: (choice: Nat64Choice) => void;
  onValueChange: (value: string) => void;
}) {
  return (
    <fieldset className="auth-method dns-policy nat64-policy">
      <legend>{t("dns.nat64.legend")}</legend>
      {allowPreserve ? (
        <div className="segmented-control dns-segmented with-preserve">
          {(["preserve", "replace", "clear"] as const).map((mode) => (
            <button
              key={mode}
              type="button"
              aria-pressed={choice === mode}
              onClick={() => onChoiceChange(mode)}
            >
              {t(`dns.nat64.mode.${mode}`)}
            </button>
          ))}
        </div>
      ) : null}
      <p className="dns-policy-note">{t(`dns.nat64.note.${allowPreserve ? choice : "setup"}`)}</p>
      {choice === "replace" ? (
        <Field label={t("dns.nat64.label")} hint={t("dns.nat64.hint")} error={value.trim() && !nat64PrefixIsValid(value) ? t("dns.nat64.invalid") : undefined}>
          <input
            className="mono"
            value={value}
            onChange={(event) => onValueChange(event.target.value)}
            placeholder={t("dns.example", { value: "64:ff9b::/96" })}
            autoCapitalize="none"
            autoComplete="off"
            spellCheck={false}
          />
        </Field>
      ) : null}
    </fieldset>
  );
}

export function DnsPolicyFields({
  choice,
  endpoints,
  allowPreserve,
  onChoiceChange,
  onEndpointChange,
}: {
  choice: DnsPolicyChoice;
  endpoints: DnsEndpointDraft[];
  allowPreserve: boolean;
  onChoiceChange: (choice: DnsPolicyChoice) => void;
  onEndpointChange: (
    index: number,
    field: keyof DnsEndpointDraft,
    value: string,
  ) => void;
}) {
  return (
    <fieldset className="auth-method dns-policy">
      <legend>{t("dns.resolver.legend")}</legend>
      <div
        className={`segmented-control dns-segmented ${allowPreserve ? "with-preserve" : ""}`}
      >
        {allowPreserve ? (
          <button
            type="button"
            aria-pressed={choice === "preserve"}
            onClick={() => onChoiceChange("preserve")}
          >
            {t("dns.resolver.mode.preserve")}
          </button>
        ) : null}
        <button
          type="button"
          aria-pressed={choice === "recursive"}
          onClick={() => onChoiceChange("recursive")}
        >
          {t("dns.resolver.mode.recursive")}
        </button>
        <button
          type="button"
          aria-pressed={choice === "dns_over_tls"}
          onClick={() => onChoiceChange("dns_over_tls")}
        >
          {t("dns.resolver.mode.dnsOverTls")}
        </button>
        <button
          type="button"
          aria-pressed={choice === "dns_over_https"}
          onClick={() => onChoiceChange("dns_over_https")}
        >
          {t("dns.resolver.mode.dnsOverHttps")}
        </button>
      </div>
      <p className="dns-policy-note">
        {choice === "preserve"
          ? t("dns.resolver.note.preserve")
          : choice === "recursive"
            ? t("dns.resolver.note.recursive")
            : choice === "dns_over_tls"
              ? t("dns.resolver.note.dnsOverTls")
              : t("dns.resolver.note.dnsOverHttps")}
      </p>
      {choice === "dns_over_tls" || choice === "dns_over_https" ? (
        <div className="dns-endpoints">
          {endpoints.map((endpoint, index) => { const errors = endpointErrors(choice, endpoints, index); return (
            <div className="dns-endpoint" key={index}>
              <strong>
                {t(index === 1 ? "dns.resolver.endpointOptional" : "dns.resolver.endpoint", { number: formatNumber(index + 1) })}
              </strong>
              <div
                className={`field-grid dns-endpoint-fields ${choice === "dns_over_https" ? "with-path" : ""}`}
              >
                <Field label={t("dns.resolver.address")} error={errors.address}>
                  <input
                    value={endpoint.address}
                    onChange={(event) =>
                      onEndpointChange(index, "address", event.target.value)
                    }
                    placeholder={t("dns.example", { value: index === 0 ? "1.1.1.1" : "1.0.0.1" })}
                    autoCapitalize="none"
                    autoComplete="off"
                    spellCheck={false}
                  />
                </Field>
                <Field label={t("dns.resolver.tlsName")} error={errors.name}>
                  <input
                    value={endpoint.authenticationName}
                    onChange={(event) =>
                      onEndpointChange(
                        index,
                        "authenticationName",
                        event.target.value,
                      )
                    }
                    placeholder={t("dns.example", { value: choice === "dns_over_https" ? "cloudflare-dns.com" : "one.one.one.one" })}
                    autoCapitalize="none"
                    autoComplete="off"
                    spellCheck={false}
                  />
                </Field>
                {choice === "dns_over_https" ? (
                  <Field label={t("dns.resolver.httpsPath")} error={errors.path}>
                    <input
                      value={endpoint.path}
                      onChange={(event) =>
                        onEndpointChange(index, "path", event.target.value)
                      }
                      placeholder={t("dns.example", { value: defaultDohPath })}
                      autoCapitalize="none"
                      autoComplete="off"
                      spellCheck={false}
                    />
                  </Field>
                ) : null}
              </div>
            </div>
          ); })}
        </div>
      ) : null}
    </fieldset>
  );
}
