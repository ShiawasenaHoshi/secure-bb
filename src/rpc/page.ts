// The page's own RPCs: the overview, the journal and guard checks, the ping, the registration of the second factor, and the approval session.
// What a page may ask without touching any plugin.
import { buildExport, writeExport } from "../export.js";
import { rpcContract } from "../contract.js";
import { GateError } from "../errors.js";
import { encodeQr } from "../../guard/src/qr.ts";
import type { ExperimentalPluginRpcHandlersWithContext } from "@get-bb/plugin-sdk";
import type { RpcCtx } from "./guard-helpers.js";

const PAGE_PING_TTL_MS = 45_000;

export function pageRpc(c: RpcCtx) {
  const { alive, bb, changed, dataDir, gate, guardLink, guardTouched, journal, needCode, needGuard, now, overview, proofOf, state, store, wrap } = c;
  return {
    overview: () => overview(),
    "journal.verify": () => {
      const r = journal(true);
      changed();
      return r;
    },
    // Hides the named pauses of the plugin from the page: a real alarm, so a code or a touch. In guard mode the guard checks it (`touch`), here we only say with which.
    "alive.review": wrap(async ({ ats, code, passkey }) => {
      const proof = proofOf(code, passkey);
      if (guardLink) {
        if (proof === undefined) throw new GateError("invalid_code", "a code or a touch is needed: this hides a real alarm");
        await guardLink.touch("alive.review", proof);
      } else gate.touch("alive.review", needCode(code));
      const reviewed = alive.reviewGaps(ats, passkey !== undefined ? "passkey" : "code");
      changed();
      return { ok: true as const, reviewed };
    }),
    "alive.ack": () => {
      alive.ackGaps();
      changed();
      return { ok: true as const };
    },
    "guard.verify": async () => {
      if (!guardLink) return { error: "not in guard mode" };
      try {
        const r = await guardLink.verifyJournal();
        changed();
        return r;
      } catch (err) {
        return { error: err instanceof Error ? err.message : String(err) };
      }
    },
    "setup-check": wrap(({ code }) => {
      // The test touch of `sbb-guard setup`. The touch itself was checked at the guard (and is in its journal, which is what the console waits for);
      // with no touch (nothing came, or this is a bb without a guard) nothing happens and the answer says so. No side effect but a line in our journal.
      needGuard();
      if (!guardTouched(code)) throw new GateError("invalid_code", "a touch is needed: press «Проверить касание» on the page");
      store.log("setup.check", null, null, { via: "guard touch" });
      return { ok: true as const };
    }),
    "approvals.export": wrap(({ code }) => {
      // The code was checked by the guard (guard mode) or is checked here (without a guard): either way `touch` takes it.
      gate.touch("approvals.export", needCode(code));
      const result = buildExport(store.listApprovals(5000), now());
      const path = writeExport(dataDir, result, now());
      store.log("approvals.export", null, null, { count: result.count, digest: result.digest });
      return { path, digest: result.digest, count: result.count };
    }),
    "page.ping": () => {
      state.lastPagePing = now();
      return { ok: true as const };
    },
    "totp.begin": wrap(async () => {
      if (guardLink) throw new GateError("conflict", "в режиме сторожа второй фактор регистрируется только на консоли: `sudo sbb-guard totp-register`; через bb секрет не проходит");
      // "Attended" = the secure-bb page pinged us moments ago. A registration
      // started without it must be restarted from the page before it can be confirmed.
      const attended = now() - state.lastPagePing < PAGE_PING_TTL_MS;
      const { secret, uri } = await gate.beginRegistration({ attended, caller: "client" });
      changed();
      return { secret, uri, matrix: encodeQr(uri) };
    }),
    "totp.confirm": wrap(({ code }) => {
      if (guardLink) throw new GateError("conflict", "в режиме сторожа второй фактор регистрируется только на консоли: `sudo sbb-guard totp-register`");
      gate.confirmRegistration(code);
      changed();
      return { ok: true as const };
    }),
    "session.open": wrap(async ({ code, passkey, hour }) => {
      if (guardLink) {
        // The guard issues it for a fresh touch (a code, or a signature bound to "open a session") and keeps only the hash of the token.
        const proof = proofOf(code, passkey);
        if (proof === undefined) throw new GateError("invalid_code", "a code or a touch is needed: the guard checks it");
        const opened = await gate.openGuardSession(proof, hour === true);
        changed();
        return opened;
      }
      if (code === undefined) throw new GateError("invalid_code", "a code is needed");
      const opened = await gate.openSession(code, hour === true);
      changed();
      return opened;
    }),
    "session.close": async () => {
      if (guardLink) await gate.closeGuardSessions("locked").catch(() => undefined);
      gate.closeSessions("locked");
      changed();
      return { ok: true as const };
    },
  } satisfies Partial<ExperimentalPluginRpcHandlersWithContext<typeof rpcContract>>;
}
