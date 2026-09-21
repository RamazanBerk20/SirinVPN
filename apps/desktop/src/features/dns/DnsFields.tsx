import { dnsEndpointAddressIsUsable, dnsOverHttpsPathIsValid } from "../../dns";
import { validateHost } from "../../format";
import { type DnsUpstream } from "../../types";
import { Field } from "../../components/ui";

export type DnsPolicyChoice =
  "preserve" | "recursive" | "dns_over_tls" | "dns_over_https";

export type PrivateDnsRecordChoice = "preserve" | "replace" | "clear";

export interface DnsEndpointDraft {
  address: string;
  authenticationName: string;
  path: string;
}

export function newDnsEndpointDrafts(): DnsEndpointDraft[] {
  return [
    { address: "", authenticationName: "", path: "/dns-query" },
    { address: "", authenticationName: "", path: "/dns-query" },
  ];
}

export function dnsDraftIsValid(
  choice: DnsPolicyChoice,
  endpoints: DnsEndpointDraft[],
): boolean {
  if (choice !== "dns_over_tls" && choice !== "dns_over_https") return true;
  const populated = endpoints.filter(
    (endpoint) => endpoint.address.trim() || endpoint.authenticationName.trim(),
  );
  const normalized = populated.map((endpoint) =>
    [
      endpoint.address.trim().toLowerCase(),
      endpoint.authenticationName.trim().toLowerCase(),
      choice === "dns_over_https" ? endpoint.path.trim() : "",
    ].join("#"),
  );
  return (
    populated.length > 0 &&
    populated.every(
      (endpoint) =>
        dnsEndpointAddressIsUsable(endpoint.address) &&
        validateHost(endpoint.authenticationName) &&
        !endpoint.authenticationName.trim().endsWith(".") &&
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

export function privateDnsRecordSummary(count: number): string {
  if (count === 0) return "no private DNS records";
  return `${count} private DNS ${count === 1 ? "record" : "records"}`;
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
      <legend>Private DNS records</legend>
      {allowPreserve ? (
        <div className="segmented-control dns-segmented with-preserve">
          <button
            type="button"
            aria-pressed={choice === "preserve"}
            onClick={() => onChoiceChange("preserve")}
          >
            Keep current
          </button>
          <button
            type="button"
            aria-pressed={choice === "replace"}
            onClick={() => onChoiceChange("replace")}
          >
            Replace
          </button>
          <button
            type="button"
            aria-pressed={choice === "clear"}
            onClick={() => onChoiceChange("clear")}
          >
            Clear
          </button>
        </div>
      ) : null}
      <p className="dns-policy-note">
        {choice === "preserve"
          ? "Repair leaves every private record unchanged."
          : choice === "clear"
            ? "Repair removes every SirinVPN-managed private record."
            : "Optional A/AAAA records are answered only by the resolver inside your VPN."}
      </p>
      {choice === "replace" ? (
        <Field
          label="One DNS-name=IP record per line"
          hint="Up to 64 records. Example: nas.home=10.20.30.40"
        >
          <textarea
            className="private-dns-record-input mono"
            value={value}
            onChange={(event) => onValueChange(event.target.value)}
            placeholder={"nas.home=10.20.30.40\nserver.home=fd00::10"}
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
      <legend>Private DNS upstream</legend>
      <div
        className={`segmented-control dns-segmented ${allowPreserve ? "with-preserve" : ""}`}
      >
        {allowPreserve ? (
          <button
            type="button"
            aria-pressed={choice === "preserve"}
            onClick={() => onChoiceChange("preserve")}
          >
            Keep current
          </button>
        ) : null}
        <button
          type="button"
          aria-pressed={choice === "recursive"}
          onClick={() => onChoiceChange("recursive")}
        >
          Recursive
        </button>
        <button
          type="button"
          aria-pressed={choice === "dns_over_tls"}
          onClick={() => onChoiceChange("dns_over_tls")}
        >
          DNS over TLS
        </button>
        <button
          type="button"
          aria-pressed={choice === "dns_over_https"}
          onClick={() => onChoiceChange("dns_over_https")}
        >
          DNS over HTTPS
        </button>
      </div>
      <p className="dns-policy-note">
        {choice === "preserve"
          ? "Repair leaves the VPS DNS policy unchanged."
          : choice === "recursive"
            ? "The VPS resolves DNS itself with DNSSEC validation and no configured forwarding provider."
            : choice === "dns_over_tls"
              ? "Unbound authenticates each configured resolver on port 853. It will not fall back to plaintext forwarding."
              : "SirinVPN posts DNS wire messages over authenticated HTTPS on port 443 to the exact resolver IPs. It uses no system DNS, HTTP proxy, or plaintext fallback."}
      </p>
      {choice === "dns_over_tls" || choice === "dns_over_https" ? (
        <div className="dns-endpoints">
          {endpoints.map((endpoint, index) => (
            <div className="dns-endpoint" key={index}>
              <strong>
                Endpoint {index + 1}
                {index === 1 ? " · optional" : ""}
              </strong>
              <div
                className={`field-grid dns-endpoint-fields ${choice === "dns_over_https" ? "with-path" : ""}`}
              >
                <Field label="Resolver IP address">
                  <input
                    value={endpoint.address}
                    onChange={(event) =>
                      onEndpointChange(index, "address", event.target.value)
                    }
                    placeholder={index === 0 ? "1.1.1.1" : "1.0.0.1"}
                    autoCapitalize="none"
                    autoComplete="off"
                    spellCheck={false}
                  />
                </Field>
                <Field label="TLS authentication name">
                  <input
                    value={endpoint.authenticationName}
                    onChange={(event) =>
                      onEndpointChange(
                        index,
                        "authenticationName",
                        event.target.value,
                      )
                    }
                    placeholder={
                      choice === "dns_over_https"
                        ? "cloudflare-dns.com"
                        : "one.one.one.one"
                    }
                    autoCapitalize="none"
                    autoComplete="off"
                    spellCheck={false}
                  />
                </Field>
                {choice === "dns_over_https" ? (
                  <Field label="HTTPS path">
                    <input
                      value={endpoint.path}
                      onChange={(event) =>
                        onEndpointChange(index, "path", event.target.value)
                      }
                      placeholder="/dns-query"
                      autoCapitalize="none"
                      autoComplete="off"
                      spellCheck={false}
                    />
                  </Field>
                ) : null}
              </div>
            </div>
          ))}
        </div>
      ) : null}
    </fieldset>
  );
}
