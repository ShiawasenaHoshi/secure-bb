import type { PublishSettings, PublishState } from "./types.js";

/** One terse line for agents: no address, no reasons (those are for the person on the page). */
export function publishLine(s: PublishSettings, state: PublishState): string {
  const label = state === "off" ? "off" : state === "ready" ? "on" : state === "not-configured" ? "on, not configured on the server" : "on, no repository address";
  return `publishing of frozen versions: ${label}${s.enabled && s.onApprove ? "; also on approval" : ""}`;
}
