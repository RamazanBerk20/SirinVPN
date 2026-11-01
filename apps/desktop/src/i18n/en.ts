import app from "../locales/en/app.json";
import common from "../locales/en/common.json";
import connection from "../locales/en/connection.json";
import devices from "../locales/en/devices.json";
import dns from "../locales/en/dns.json";
import format from "../locales/en/format.json";
import help from "../locales/en/help.json";
import home from "../locales/en/home.json";
import maintenance from "../locales/en/maintenance.json";
import native from "../locales/en/native.json";
import onboarding from "../locales/en/onboarding.json";
import release from "../locales/en/release.json";
import servers from "../locales/en/servers.json";
import settings from "../locales/en/settings.json";
import ssh from "../locales/en/ssh.json";
import vps from "../locales/en/vps.json";

/** English source catalog. Each namespace file maps to the first segment of a message key. */
export const en = { app, common, connection, devices, dns, format, help, home, maintenance, native, onboarding, release, servers, settings, ssh, vps };
export type Messages = typeof en;
