import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import { useState } from "react";
import { TransportSetupFields, newTransportDraft, transportDraftIsValid, transportSetupFromDraft } from "./TransportSetupFields";

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
  expect(transportSetupFromDraft(https)).toMatchObject({ https: { server_name: "vpn.example.org", path: "/connect" }, https_certificate_path: "/etc/cert.pem" });
});

it("shows HTTPS fields only when enabled and accepts custom ports", () => {
  function Form() {
    const [draft, setDraft] = useState(newTransportDraft);
    return <TransportSetupFields value={draft} onChange={setDraft} />;
  }
  render(<Form />);
  fireEvent.click(screen.getByText("Public addresses, transport ports and HTTPS"));
  expect(screen.queryByRole("textbox", { name: "HTTPS hostname" })).toBeNull();
  fireEvent.click(screen.getByRole("checkbox", { name: "Use HTTPS mode" }));
  fireEvent.change(screen.getByRole("textbox", { name: "HTTPS hostname" }), { target: { value: "vpn.example.org" } });
  fireEvent.change(screen.getByRole("textbox", { name: "TCP and TLS port" }), { target: { value: "4443" } });
  expect(screen.queryByRole("status")).toBeNull();
});
