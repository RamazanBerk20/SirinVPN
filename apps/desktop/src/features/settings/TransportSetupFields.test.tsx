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
  expect(transportDraftIsValid({ ...https, cdn: true, publicHost: "VPN.example.org" })).toBe(false);
  expect(transportDraftIsValid({ ...https, cdn: false, publicHost: "vpn.example.org" })).toBe(true);
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
  fireEvent.change(screen.getByRole("textbox", { name: t("ssh.transport.tcpTlsPort") }), { target: { value: "443" } });
  expect(screen.queryByText(t("ssh.transport.cdnPortNote"))).toBeNull();
  fireEvent.change(screen.getByRole("textbox", { name: t("ssh.transport.tcpTlsPort") }), { target: { value: "4443" } });
  expect(screen.getByText(t("ssh.transport.cdnPortNote"))).toBeTruthy();
  expect(screen.queryByRole("status")).toBeNull();
});

it("keeps an existing server's CDN mode when repairing", () => {
  const profile = { endpoint: { host: "203.0.113.8", wireguard_port: 51820 }, tls_like: { https: { server_name: "vpn.example.org", path: "/connect", cdn: true } } };
  const draft = newTransportDraft(profile as never);
  expect(draft.cdn).toBe(true);
  expect(transportSetupFromDraft(draft).https?.cdn).toBe(true);
});

it("keeps an existing server's ports and QUIC setting until the Owner turns QUIC on", () => {
  const fresh = newTransportDraft();
  expect(fresh).toMatchObject({ obfuscated: "51821", quic: true });
  expect(transportSetupFromDraft(fresh).quic).toBe(true);
  expect(transportDraftIsValid({ ...fresh, obfuscated: "443" })).toBe(false);
  const legacy = { endpoint: { host: "203.0.113.8", wireguard_port: 51820 }, obfuscated_udp: { port: 443 }, tcp_fallback: { port: 443 }, tls_like: {} };
  const kept = newTransportDraft(legacy as never);
  expect(kept).toMatchObject({ obfuscated: "443", quic: false });
  expect(transportDraftIsValid(kept)).toBe(true);
  expect(transportSetupFromDraft(kept)).toMatchObject({ obfuscated_udp_port: 443, quic: false });
  expect(newTransportDraft({ ...legacy, obfuscated_udp: { port: 51821 }, tls_like: { quic: true } } as never).quic).toBe(true);
  function Form() {
    const [draft, setDraft] = useState(() => newTransportDraft(legacy as never));
    return <TransportSetupFields value={draft} onChange={setDraft} existing />;
  }
  render(<Form />);
  fireEvent.click(screen.getByText(t("ssh.transport.summary")));
  expect(screen.queryByText(t("ssh.transport.quicNote"))).toBeNull();
  fireEvent.click(screen.getByRole("checkbox", { name: t("ssh.transport.quic") }));
  expect(screen.getByText(t("ssh.transport.quicNote"))).toBeTruthy();
  expect((screen.getByRole("textbox", { name: t("ssh.transport.obfuscatedPort") }) as HTMLInputElement).value).toBe("51821");
  expect(screen.queryByRole("status")).toBeNull();
});
