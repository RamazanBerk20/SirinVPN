/** Guards hold callbacks only in memory; recovery secrets are never persisted. */
const guards = new Set<() => boolean>();
export function registerNavigationGuard(guard: () => boolean) {
  guards.add(guard);
  return () => { guards.delete(guard); };
}
export function confirmNavigation() {
  return [...guards].every((guard) => guard());
}
