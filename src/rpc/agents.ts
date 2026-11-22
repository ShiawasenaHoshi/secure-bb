// The RPCs about the agents' settings: scan, accept, reject, restore, the parts of a file («Оставить» / «Вернуть» / «Отозвать»), and «Остановить агентов».
// The guard watches the files and does the writing; here the call is turned into the guard's, with the touch it needs.
import { agentAcceptProblem } from "../ux.js";
import { rpcContract } from "../contract.js";
import { GateError } from "../errors.js";
import type { ExperimentalPluginRpcHandlersWithContext } from "@get-bb/plugin-sdk";
import type { RpcCtx } from "./guard-helpers.js";

export function agentsRpc(c: RpcCtx) {
  const { agents, bb, changed, guardLink, proofOf, proofOrSession, state, stopper, wrap } = c;
  return {
    "agents.scan": wrap(async () => {
      if (!agents) throw new GateError("invalid", "наблюдение за конфигурациями агентов работает в режиме сторожа: наблюдатель живёт в нём");
      const view = await agents.refresh(true);
      state.sweepTaintNow();
      return view;
    }),
    // A touch for exactly these differences: the guard checks the code or the signature (bound to the ids) and moves its baseline. Nothing is accepted here.
    // «Это не я — отклонить»: no code (tightening). The difference stays open: the alarm and the pollution stay until the file itself is fixed.
    "agents.reject": wrap(async ({ ids }) => {
      if (!agents || !guardLink) throw new GateError("invalid", "отклонить расхождения можно только через сторожа");
      if (ids.length === 0) throw new GateError("invalid", "нет расхождений для отклонения");
      const r = await guardLink.agentsReject(ids);
      await agents.refresh(false);
      changed();
      return { ok: true as const, rejected: r.rejected, note: "отклонено: в эталон не пошло; тревога остаётся, пока файл не исправят" };
    }),
    "agents.accept": wrap(async ({ ids, code, passkey }) => {
      if (!agents || !guardLink) throw new GateError("invalid", "принять расхождения можно только через сторожа");
      if (ids.length === 0) throw new GateError("invalid", "нет расхождений для принятия");
      const proof = proofOf(code, passkey);
      if (proof === undefined) throw new GateError("invalid_code", "a code or a touch is needed: the guard checks it");
      // The guard refuses it too (and is the one that counts); this only avoids sending a code that cannot be used.
      const problem = agentAcceptProblem(ids, (await agents.refresh(false)).state?.drifts ?? []);
      if (problem) throw new GateError("invalid", problem);
      const r = await guardLink.agentsAccept(ids, proof);
      await agents.refresh(false);
      changed();
      return { ok: true as const, accepted: r.accepted, note: `принято в эталон: ${r.accepted}` };
    }),
    // «Вернуть как было»: a touch for this one difference. Nothing is written here: the guard puts its own baseline back through the restore helper.
    "agents.restore": wrap(async ({ id, code, passkey }) => {
      if (!agents || !guardLink) throw new GateError("invalid", "вернуть файл можно только через сторожа");
      const proof = proofOf(code, passkey);
      if (proof === undefined) throw new GateError("invalid_code", "a code or a touch is needed: the guard checks it");
      const r = await guardLink.agentsRestore(id, proof);
      await agents.refresh(false);
      changed();
      return {
        ok: true as const,
        resolved: r.resolved,
        action: r.action,
        note: r.resolved ? "Готово: настройки агента возвращены, тревога снята" : "Файл возвращён, но сторож всё ещё видит расхождение (возможно, агент изменил его снова): посмотрите карточку",
      };
    }),
    // One part of a settings file. «Вернуть» (theirs) tightens: no code. «Оставить» (mine): a touch; a session only for a part that is not dangerous (the guard checks the flag itself).
    "agents.rollbackPart": wrap(async ({ id, partId, fileSha, code, passkey }) => {
      if (!agents || !guardLink) throw new GateError("invalid", "вернуть часть файла можно только через сторожа");
      // A code or a touch goes along when there is one; the guard decides whether this one needs it (a return that makes the agent more dangerous does).
      const r = await guardLink.agentsRollbackPart(id, partId, fileSha, proofOf(code, passkey));
      await agents.refresh(false);
      changed();
      return { ok: true as const, resolved: r.resolved, remaining: r.remaining, note: r.resolved ? "Готово: возвращено, тревога снята" : "Готово: возвращено" };
    }),
    "agents.revokeKept": wrap(async ({ id, code, passkey }) => {
      if (!agents || !guardLink) throw new GateError("invalid", "отозвать можно только через сторожа");
      const r = await guardLink.agentsRevokeKept(id, proofOf(code, passkey));
      await agents.refresh(true);
      changed();
      return { ok: true as const, note: r.inFile ? "Отозвано: это ушло из файла настроек агента" : "Отозвано: в файле этого уже не было" };
    }),
    "agents.keepPart": wrap(async ({ id, partId, fileSha, danger, code, passkey, session }) => {
      if (!agents || !guardLink) throw new GateError("invalid", "оставить часть файла можно только через сторожа");
      const proof = proofOrSession({ code, passkey, session }, danger);
      if (proof === undefined) throw new GateError("invalid_code", "a code or a touch is needed: the guard checks it");
      const r = await guardLink.agentsKeepPart(id, partId, fileSha, danger, proof);
      await agents.refresh(true);
      changed();
      return { ok: true as const, accepted: r.accepted, remaining: r.remaining, note: r.accepted ? "Оставлено: больше расхождений в этом файле нет" : "Оставлено" };
    }),
    // «Остановить агентов»: no code (a tightening). Every running thread is stopped; new turns are held while the critical difference is open.
    "agents.stop": wrap(async () => {
      const r = await stopper.stopAll();
      if (agents) await agents.refresh(false);
      changed();
      const note = `Агенты остановлены (${r.stopped.length}${r.failed.length > 0 ? `, не удалось остановить: ${r.failed.length}` : ""}). Пока настройки не исправлены, лучше не запускать их снова.${state.holdAvailable ? " Новые сообщения агентам будут держаться, пока тревога не снята." : " Но удержать новые сообщения этот bb не позволяет: агенты могут быть запущены снова."}`;
      return { ok: true as const, stopped: r.stopped.length, failed: r.failed.length, holdAvailable: state.holdAvailable, note };
    }),
  } satisfies Partial<ExperimentalPluginRpcHandlersWithContext<typeof rpcContract>>;
}
