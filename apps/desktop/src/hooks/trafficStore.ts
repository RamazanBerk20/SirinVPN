import { useSyncExternalStore } from "react";

export class TrafficStore<T> {
  private value: T | null = null;
  private listeners = new Set<() => void>();
  getSnapshot = () => this.value;
  subscribe = (listener: () => void) => {
    this.listeners.add(listener);
    return () => { this.listeners.delete(listener); };
  };
  publish(value: T | null) {
    if (this.value === value) return;
    this.value = value;
    this.listeners.forEach(listener => listener());
  }
}
const idle = () => () => {};
const empty = () => null;
export function useTrafficStore<T>(store?: TrafficStore<T>) {
  return useSyncExternalStore(store?.subscribe ?? idle, store?.getSnapshot ?? empty);
}

export function localControlKey(status: import("../types").LocalTunnelStatus): string {
  const { rx_bytes, tx_bytes, rx_packets, tx_packets, rx_bytes_per_second, tx_bytes_per_second, counter_sampled_at_ms, tunnel_uptime_seconds, observed_at_ms, ...control } = status;
  void rx_bytes; void tx_bytes; void rx_packets; void tx_packets; void rx_bytes_per_second; void tx_bytes_per_second;
  // The observation clock belongs to traffic consumers, just like the counters.
  void counter_sampled_at_ms; void tunnel_uptime_seconds; void observed_at_ms;
  return JSON.stringify(control);
}
