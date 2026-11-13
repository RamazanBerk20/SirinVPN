import { describe, expect, it } from "vitest";
import { emptyLocalStatus } from "./useDesktopStatus";
import { feedFreshness, initialStatusFeed, statusFeedReducer as reduce, type StatusFeed } from "./statusFeed";
import type { LocalTunnelStatus, ServerStatus } from "../types";

const connected = (server_id: string, extra: Partial<LocalTunnelStatus> = {}): LocalTunnelStatus =>
  ({ ...emptyLocalStatus, state: "connected", server_id, ...extra });
const reading = (local: LocalTunnelStatus) => ({ type: "localEvent" as const, event: { kind: "reading" as const, local } });
const remote = { server_name: "A" } as ServerStatus;
const start = initialStatusFeed({ ...emptyLocalStatus, state: "unknown" });
const live = (server = "a") => reduce(start, reading(connected(server)));
const withRemote = (feed: StatusFeed) => reduce(feed, { type: "serverEvent", epoch: feed.epoch, event: { kind: "status", remote, mode: "live", at: 5 } });

describe("statusFeedReducer: local feed", () => {
  it("starts subscribing and goes live on a reading", () => {
    expect(feedFreshness(start)).toEqual({ refreshing: true, updatedAt: null, management: "idle", mode: undefined });
    const feed = live();
    expect(feed.localFeed).toEqual({ state: "live" });
    expect(feed.serverFeed).toEqual({ state: "connecting", serverId: "a", epoch: 1 });
    expect(feedFreshness(feed)).toMatchObject({ refreshing: false, management: "refreshing" });
  });
  it("keeps the same object for traffic-only readings", () => {
    const feed = live();
    expect(reduce(feed, reading(connected("a", { rx_bytes: 99, tunnel_uptime_seconds: 3 })))).toBe(feed);
    expect(reduce(feed, reading(connected("a", { kill_switch_enabled: true }))).local.kill_switch_enabled).toBe(true);
  });
  it("refresh → subscribing, timer → stale with the last reading kept, reading → live", () => {
    const refreshing = reduce(withRemote(live()), { type: "refresh" });
    expect(reduce(refreshing, { type: "refresh" })).toBe(refreshing);
    const stale = reduce(refreshing, { type: "timer" });
    expect(stale.localFeed).toEqual({ state: "stale" });
    expect(stale.local.state).toBe("connected");
    expect(feedFreshness(stale)).toMatchObject({ refreshing: false, management: "ready" });
    expect(reduce(stale, { type: "timer" })).toBe(stale);
    expect(reduce(live(), { type: "timer" }).localFeed).toEqual({ state: "live" });
    expect(reduce(stale, reading(connected("a"))).localFeed).toEqual({ state: "live" });
  });
  it("fails to unknown, drops the server, and reports management unavailable", () => {
    const failed = reduce(withRemote(live()), { type: "localEvent", event: { kind: "failed" } });
    expect(failed.local).toMatchObject({ state: "unknown", server_id: "a" });
    expect(failed.remote).toBeNull();
    expect(failed.serverFeed).toEqual({ state: "off" });
    expect(feedFreshness(failed).management).toBe("unavailable");
    // Recovering opens a new subscription.
    expect(reduce(failed, reading(connected("a"))).serverFeed).toEqual({ state: "connecting", serverId: "a", epoch: 2 });
  });
  it("pauses while hidden and subscribes again when visible", () => {
    const hidden = reduce(withRemote(live()), { type: "visibility", visible: false });
    expect(hidden).toMatchObject({ localFeed: { state: "paused" }, serverFeed: { state: "off" }, remote: null, local: { state: "unknown" } });
    expect(feedFreshness(hidden).management).toBe("idle");
    expect(reduce(hidden, { type: "visibility", visible: false })).toBe(hidden);
    const visible = reduce(hidden, { type: "visibility", visible: true });
    expect(visible.localFeed).toEqual({ state: "subscribing" });
    expect(reduce(visible, { type: "visibility", visible: true })).toBe(visible);
  });
  it("turns the server feed off when the tunnel disconnects or switches server", () => {
    const off = reduce(withRemote(live()), reading(emptyLocalStatus));
    expect(off).toMatchObject({ remote: null, serverFeed: { state: "off" }, epoch: 1 });
    const switched = reduce(withRemote(live()), reading(connected("b")));
    expect(switched).toMatchObject({ remote: null, serverFeed: { state: "connecting", serverId: "b", epoch: 2 } });
  });
});

describe("statusFeedReducer: server feed", () => {
  it("goes live, reconnects and reconnects again", () => {
    const ready = withRemote(live());
    expect(ready.serverFeed).toEqual({ state: "live", serverId: "a", epoch: 1, mode: "live", updatedAt: 5 });
    expect(feedFreshness(ready)).toEqual({ refreshing: false, updatedAt: 5, management: "ready", mode: "live" });
    const lost = reduce(ready, { type: "serverEvent", epoch: 1, event: { kind: "state", state: "reconnecting" } });
    expect(lost).toMatchObject({ remote: null, serverFeed: { state: "reconnecting", serverId: "a", epoch: 1 } });
    expect(feedFreshness(lost)).toMatchObject({ management: "reconnecting", updatedAt: null, mode: undefined });
    const again = reduce(lost, { type: "serverEvent", epoch: 1, event: { kind: "state", state: "connecting" } });
    expect(feedFreshness(again).management).toBe("refreshing");
  });
  it("drops events from an older subscription or while off", () => {
    const switched = reduce(withRemote(live()), reading(connected("b")));
    expect(reduce(switched, { type: "serverEvent", epoch: 1, event: { kind: "status", remote, at: 9 } })).toBe(switched);
    const off = reduce(live(), reading(emptyLocalStatus));
    expect(reduce(off, { type: "serverEvent", epoch: 1, event: { kind: "state", state: "reconnecting" } })).toBe(off);
  });
});
