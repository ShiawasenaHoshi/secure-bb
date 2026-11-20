// Protection-level ("ступень") assessment. Pure: takes facts collected by
// probe.ts and returns the honest status. Nothing here assumes this machine's
// configuration; every fact can be "unknown" and is reported as such.
import { T } from "./text.js";

export type CheckState = "ok" | "warn" | "bad" | "unknown";
export interface Check {
  id: string;
  label: string;
  state: CheckState;
  detail: string;
}

export interface Probe {
  /** `bb.experimental_hooks.on("plugin.activate", …)` registered without throwing. */
  hookRegistered: boolean;
  env: Record<string, string | undefined>;
  serverUid: number | null;
  /** uid of the host daemon (the agents), or null when it could not be determined. */
  agentUid: number | null;
  accountState: "signed-in" | "signed-out" | "unknown";
  /** Built-in plugins by id (without any `bb--` prefix) → enabled. */
  builtins: Record<string, boolean | undefined>;
  connectHold: { exists: boolean; serverCanDelete: boolean | null };
  bind: { address: string | null; loopbackOnly: boolean | null };
  apiAuth: "none" | "enforced" | "unknown";
  /** Third-party plugins currently running. */
  thirdParty: string[];
  telemetryConfigured: boolean | null;
}

export const SENSITIVE_BUILTINS = [
  "connect",
  "connect-next",
  "bb-account",
  "mcp",
  "bb-ai",
  "push-notifications",
  "browser-automation",
  "account-pool",
] as const;

export interface Assessment {
  stage: 0 | 1 | 2 | 3 | 4 | 5;
  afterTheFact: boolean;
  checks: Check[];
  protects: string[];
  missing: string[];
  nextStep: string;
  honest: string[];
}

const flag = (v: string | undefined): boolean => v !== undefined && !/^(0|false|no|off|)$/i.test(v.trim());

export function assess(p: Probe): Assessment {
  const guards = (p.env.BB_PLUGIN_ACTIVATION_GUARDS ?? "").split(",").map((s) => s.trim()).filter(Boolean);
  const guardOk = guards.includes("secure-bb");
  const uidKnown = p.serverUid !== null && p.agentUid !== null;
  const sameUid = uidKnown && p.serverUid === p.agentUid;
  const telemetryOff =
    p.env.BB_TELEMETRY !== undefined ? !flag(p.env.BB_TELEMETRY) : p.telemetryConfigured === null ? null : !p.telemetryConfigured;
  const sensitiveOn = SENSITIVE_BUILTINS.filter((id) => p.builtins[id] === true);
  const connectBlocked = p.connectHold.exists && p.connectHold.serverCanDelete === false;

  const checks: Check[] = [];
  const add = (id: string, label: string, state: CheckState, detail: string) => checks.push({ id, label, state, detail });

  add("hook", T.chk.hook, p.hookRegistered ? "ok" : "bad", p.hookRegistered ? T.chk.hookOk : T.chk.hookNo);
  add(
    "guard",
    T.chk.guard,
    guardOk ? "ok" : p.hookRegistered ? "bad" : "unknown",
    guardOk ? T.chk.guardOk : p.hookRegistered ? T.chk.guardNo : T.chk.guardNeedsHook,
  );
  add(
    "uid",
    T.chk.uid,
    !uidKnown ? "unknown" : sameUid ? "bad" : "ok",
    !uidKnown ? T.chk.uidUnknown : sameUid ? T.chk.uidSame(p.serverUid!) : T.chk.uidDiff(p.serverUid!, p.agentUid!),
  );
  add(
    "account",
    T.chk.account,
    p.accountState === "signed-out" ? "ok" : p.accountState === "signed-in" ? "bad" : "unknown",
    p.accountState === "signed-out" ? T.chk.accountOut : p.accountState === "signed-in" ? T.chk.accountIn : T.chk.accountUnknown,
  );
  add(
    "builtins",
    T.chk.builtins,
    sensitiveOn.length === 0 ? "ok" : "warn",
    sensitiveOn.length === 0 ? T.chk.builtinsOff : T.chk.builtinsOn(sensitiveOn.join(", ")),
  );
  add(
    "connect-hold",
    T.chk.connectHold,
    connectBlocked ? "ok" : p.connectHold.exists ? "warn" : "bad",
    connectBlocked ? T.chk.holdOk : p.connectHold.exists ? T.chk.holdDeletable : T.chk.holdMissing,
  );
  add(
    "bind",
    T.chk.bind,
    p.bind.loopbackOnly === null ? "unknown" : p.bind.loopbackOnly ? "ok" : "bad",
    p.bind.loopbackOnly === null ? T.chk.bindUnknown : p.bind.loopbackOnly ? T.chk.bindOk(p.bind.address ?? "127.0.0.1") : T.chk.bindOpen(p.bind.address ?? "*"),
  );
  add("telemetry", T.chk.telemetry, telemetryOff === null ? "unknown" : telemetryOff ? "ok" : "warn", telemetryOff === null ? T.chk.telemetryUnknown : telemetryOff ? T.chk.telemetryOff : T.chk.telemetryOn);
  add(
    "marketplace",
    T.chk.marketplace,
    p.env.BB_MARKETPLACE_URL === undefined ? "unknown" : "ok",
    p.env.BB_MARKETPLACE_URL === undefined ? T.chk.marketplaceDefault : T.chk.marketplaceCustom,
  );
  add("api-auth", T.chk.apiAuth, p.apiAuth === "enforced" ? "ok" : p.apiAuth === "none" ? "bad" : "unknown", p.apiAuth === "enforced" ? T.chk.apiAuthOk : p.apiAuth === "none" ? T.chk.apiAuthNo : T.chk.apiAuthUnknown);
  add(
    "third-party",
    T.chk.thirdParty,
    p.thirdParty.length === 0 ? "ok" : "warn",
    p.thirdParty.length === 0 ? T.chk.thirdPartyNone : T.chk.thirdPartyList(p.thirdParty.join(", ")),
  );

  const s1 = p.hookRegistered;
  const s2 = s1 && guardOk;
  const s3 = s2 && uidKnown && !sameUid;
  const s4 = s3 && p.bind.loopbackOnly === true && telemetryOff === true && p.accountState === "signed-out" && connectBlocked && sensitiveOn.length === 0;
  const s5 = s4 && p.apiAuth === "enforced";
  const stage = (s5 ? 5 : s4 ? 4 : s3 ? 3 : s2 ? 2 : s1 ? 1 : 0) as Assessment["stage"];

  const nextSteps: Record<number, string> = {
    0: T.next0,
    1: T.next1,
    2: T.next2,
    3: T.next3,
    4: T.next4,
    5: T.next5,
  };

  return {
    stage,
    afterTheFact: !p.hookRegistered,
    checks,
    protects: T.protects[stage]!,
    missing: T.missing[stage]!,
    nextStep: nextSteps[stage]!,
    honest: [...(stage < 3 ? [T.honestSameUser] : []), ...(!p.hookRegistered ? [T.honestAfterFact] : [])],
  };
}
