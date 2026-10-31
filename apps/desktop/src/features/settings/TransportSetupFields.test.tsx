import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import { useState } from "react";
import { TransportSetupFields, newTransportDraft, transportDraftIsValid, transportSetupFromDraft } from "./TransportSetupFields";
import { t } from "../../i18n";

afterEach(cleanup);

it("validates collisions, reserved ports, and matching certificate paths before provisioning", () => {
  const defaults = newTransportDraft();
  expect(transportDraftIsValid(defaults)).toBe(true);
  expect(transportDraftIsValid({ ...defaults, obfuscated: "51820" })).toBe(false);
  expect(transportDraftIsValid({ ...defaults, tcpTls: "8443" })).toBe(false);
  const https = { ...defaults, https: true, hostname: "vpn.example.org", certificate: "/etc/cert.pem", privateKey: "/etc/key.pem" };
  expect(transportDraftIsValid(https)).toBe(true);
  expect(transportDraftIsValid({ ...https, hostname: "203.0.113.8" })).toBe(false);
  expect(transportDraftIsValid({ ...https, privateKey: "" })).toBe(false);
  expect(transportDraftIsValid({ ...https, path: "/../private" })).toBe(false);
  expect(transportSetupFromDraft(https)).toMatchObject({ https: { server_name: "vpn.example.org", path: "/connect", cdn: false }, https_certificate_path: "/etc/cert.pem" });
  expect(transportSetupFromDraft({ ...https, cdn: true }).https).toEqual({ server_name: "vpn.example.org", path: "/connect", cdn: true });
});

it("shows HTTPS fields only when enabled and accepts custom ports", () => {
  function Form() {
    const [draft, setDraft] = useState(newTransportDraft);
    return <TransportSetupFields value={draft} onChange={setDraft} />;
  }
  render(<Form />);
  fireEvent.click(screen.getByText(t("ssh.transport.summary")));
  expect(screen.queryByRole("textbox", { name: t("ssh.transport.hostname") })).toBeNull();
  fireEvent.click(screen.getByRole("checkbox", { name: t("ssh.transport.https") }));
  fireEvent.change(screen.getByRole("textbox", { name: t("ssh.transport.hostname") }), { target: { value: "vpn.example.org" } });
  fireEvent.change(screen.getByRole("textbox", { name: t("ssh.transport.tcpTlsPort") }), { target: { value: "4443" } });
  expect(screen.queryByText(t("ssh.transport.cdnNote"))).toBeNull();
  fireEvent.click(screen.getByRole("checkbox", { name: t("ssh.transport.cdn") }));
  expect(screen.getByText(t("ssh.transport.cdnNote"))).toBeTruthy();
  expect(screen.queryByRole("status")).toBeNull();
});

it("keeps an existing server's CDN mode when repairing", () => {
  const profile = { endpoint: { host: "203.0.113.8", wireguard_port: 51820 }, tls_like: { https: { server_name: "vpn.example.org", path: "/connect", cdn: true } } };
  const draft = newTransportDraft(profile as never);
  expect(draft.cdn).toBe(true);
  expect(transportSetupFromDraft(draft).https?.cdn).toBe(true);
});
