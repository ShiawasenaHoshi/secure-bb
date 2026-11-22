// The gate: decides `plugin.activate`, owns approvals, trust windows and the
// touch (TOTP) rules. Pure logic over Store + injected clock; no bb imports,
// so it is testable without a server.
//
// This file is the front: `Gate` is the class everyone knows, built from layers (gate-base.ts → gate-factor.ts → gate-settings.ts → gate-checks.ts → gate-windows.ts → gate-queue.ts → decide-hook.ts),
// each calling only what is below it. Its vocabulary (`HookCtx`, `Decision`, `GateDeps`, the reasons) is gate-types.ts.

import { GateHook } from "./decide-hook.js";

export { TAMPERED_REASON, UNSAFE_DIR_REASON, GUARD_WINDOW_UNBOUND, isOpen } from "./gate-types.js";
export type { HookCtx, Decision, GateDeps, TotpState } from "./gate-types.js";

export class Gate extends GateHook {}
