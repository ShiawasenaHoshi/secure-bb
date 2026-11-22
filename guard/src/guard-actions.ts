// A touch is given for ONE action: this layer says exactly which (`normalizeAction`) and in what words the person sees it (`describe`).
// It does not check any factor: that is factor.ts, which signs and verifies these actions.
import { identityOf, MODE_RANK, normalizeEntry, TRUST_MODES, type TrustMode } from "./trust.ts";
import { rollbackDanger, type JsonPart } from "./json-parts.ts";
import { SESSION_CAP_MS, SESSION_IDLE_MS, minutesWords, sessionCoverage } from "./session-rules.ts";
import { GuardError, SETUP_CHECK_PURPOSE, type Policy, type Raw, str, pluginIdOf, intOf } from "./guard-types.ts";
import { AgentsPlanGuard } from "./agents-plan.ts";

export class ActionGuard extends AgentsPlanGuard {
  // ---- actions: normalized, described, challenged ----
  /**
   * What a signature is bound to: the action with only the fields that matter, in a fixed order, defaults resolved. The same function
   * runs when the challenge is issued and when the command arrives, so the two are compared as strings.
   */
  protected normalizeAction(raw: unknown): Record<string, unknown> {
    if (typeof raw !== "object" || raw === null || Array.isArray(raw)) throw new GuardError("invalid", "an action is a JSON object");
    const a = raw as Record<string, unknown>;
    switch (a.op) {
      case "approve":
        if (a.acknowledgeBlock !== undefined && typeof a.acknowledgeBlock !== "boolean") throw new GuardError("invalid", "acknowledgeBlock is true or false");
        return { op: "approve", requestId: intOf(a.requestId, "requestId", 1, Number.MAX_SAFE_INTEGER), ...(a.acknowledgeBlock === true ? { acknowledgeBlock: true } : {}) };
      case "approve-trust": {
        // The source comes from the queue entry, never from the caller: a touch for "trust THIS" is for what the guard names.
        const id = intOf(a.requestId, "requestId", 1, Number.MAX_SAFE_INTEGER);
        const q = this.heldRequest(id);
        const ident = identityOf(q.sourceKind, q.source, q.rootDir);
        const entry = ident === null ? null : normalizeEntry(ident.id);
        if (entry === null) throw new GuardError("invalid", "this version's source cannot be put into \"my sources\" (not github and not a directory on disk)");
        return { op: "approve-trust", requestId: id, entry };
      }
      case "session-open":
        return a.hour === true ? { op: "session-open", hour: true } : { op: "session-open" };
      case "batch-approve":
        return { op: "batch-approve", batchId: str(a.batchId, "batchId", 64, 1), setHash: str(a.setHash, "setHash", 64, 64) };
      case "open-window": {
        const scope = a.scope;
        if (scope !== undefined && scope !== "tree" && scope !== "thread") throw new GuardError("invalid", "scope is tree or thread");
        return { op: "open-window", pluginId: pluginIdOf(a.pluginId), minutes: a.minutes === undefined ? this.policy().windowMin : intOf(a.minutes, "minutes", 1, 1440), ...(scope !== undefined ? { scope } : {}), ...(this.criticalAgentsOpen() ? { alarm: true } : {}) };
      }
      case "policy": {
        if (typeof a.patch !== "object" || a.patch === null || Array.isArray(a.patch)) throw new GuardError("invalid", "patch is an object");
        const p = a.patch as Partial<Policy>;
        const patch: Partial<Policy> = {};
        if (p.windowMin !== undefined) patch.windowMin = intOf(p.windowMin, "windowMin", 1, 1440);
        if (p.capMin !== undefined) patch.capMin = intOf(p.capMin, "capMin", 1, 1440);
        if (p.mode !== undefined) {
          if (p.mode !== "sliding" && p.mode !== "fixed") throw new GuardError("invalid", "mode is sliding or fixed");
          patch.mode = p.mode;
        }
        return { op: "policy", patch };
      }
      case "touch":
        return { op: "touch", purpose: str(a.purpose, "purpose", 80, 1) };
      case "trust-mode":
        if (typeof a.mode !== "string" || !TRUST_MODES.includes(a.mode as TrustMode)) throw new GuardError("invalid", "mode is simple, detailed or strict");
        return { op: "trust-mode", mode: a.mode };
      case "sources-add":
        return { op: "sources-add", entries: this.entriesOf(a.entries) };
      case "agents-accept":
        return { op: "agents-accept", ids: this.agentIds(a.ids) };
      // Only the id: what is written comes from the guard's own baseline, never from the action.
      case "agents-restore":
        return { op: "agents-restore", id: intOf(a.id, "id", 1, Number.MAX_SAFE_INTEGER) };
      // One part of a settings file. `danger` is what the caller says; it is checked against the guard's own reading before anything is signed or spent.
      case "agents-keep-part": {
        const id = intOf(a.id, "id", 1, Number.MAX_SAFE_INTEGER);
        const partId = str(a.partId, "partId", 16, 16);
        const fileSha = str(a.fileSha, "fileSha", 16, 16);
        if (typeof a.danger !== "boolean") throw new GuardError("invalid", "danger is true or false");
        const { part, danger } = this.partOf(id, partId, fileSha);
        if (part && (danger !== null) !== a.danger) throw new GuardError("conflict", "the part is not what the page showed: look again");
        return { op: "agents-keep-part", id, partId, fileSha, danger: a.danger };
      }
      // «Вернуть» / «Отозвать»: a touch only when the RESULT makes the agent more dangerous (the guard looks at what the file would say, not at the button's name).
      case "agents-rollback-part":
        return { op: "agents-rollback-part", id: intOf(a.id, "id", 1, Number.MAX_SAFE_INTEGER), partId: str(a.partId, "partId", 16, 16), fileSha: str(a.fileSha, "fileSha", 16, 16) };
      case "agents-revoke-kept":
        return { op: "agents-revoke-kept", id: intOf(a.id, "id", 1, Number.MAX_SAFE_INTEGER) };
      default:
        throw new GuardError("invalid", "an action is approve, approve-trust, session-open, batch-approve, open-window, policy, touch, trust-mode, sources-add, agents-accept, agents-restore, agents-keep-part, agents-rollback-part or agents-revoke-kept");
    }
  }
  /** The sentence the page shows next to the touch button (in the journal after the fact too): what is about to be approved, in the guard's own words. */
  protected describe(a: Record<string, unknown>): string {
    switch (a.op) {
      case "approve": {
        const q = this.db.prepare(`SELECT * FROM queue WHERE id = ?`).get(Number(a.requestId)) as Raw | undefined;
        if (!q) throw new GuardError("not_found", `no request #${String(a.requestId)}`);
        if (q.status !== "held") throw new GuardError("conflict", `request #${String(a.requestId)} is already ${String(q.status)}`);
        return `${a.acknowledgeBlock === true ? "СНЯТЬ ОСТАНОВКУ и одобрить" : "Одобрить"} загрузку плагина «${String(q.plugin_id)}» версии ${String(q.version)} (запись #${String(q.id)}, источник ${String(q.source)}, хеш ${String(q.content_hash).slice(0, 16)}…)${a.acknowledgeBlock === true ? ": версию остановили проверки, вы берёте риск на себя" : ""}`;
      }
      case "approve-trust": {
        const q = this.db.prepare(`SELECT * FROM queue WHERE id = ?`).get(Number(a.requestId)) as Raw | undefined;
        if (!q) throw new GuardError("not_found", `no request #${String(a.requestId)}`);
        return `Одобрить версию ${String(q.version)} плагина «${String(q.plugin_id)}» (запись #${String(q.id)}, хеш ${String(q.content_hash).slice(0, 16)}…) И добавить источник ${String(a.entry)} в «мои источники»: новые версии оттуда будут проходить без вопросов, пока плагин не попросит новых прав`;
      }
      case "session-open": {
        // What the session covers is told from the table (session-rules.ts), not from a list of its own.
        const c = sessionCoverage();
        const tail = `Рутину (${c.routine.join(", ")}) она покрывает без касания; опасное (${c.fresh.join(", ")}) — всегда со свежим касанием`;
        if (a.hour === true) return `Открыть сессию подтверждения на ${minutesWords(SESSION_CAP_MS)} подряд (не продлевается). ${tail}`;
        return `Открыть сессию подтверждения: ${SESSION_IDLE_MS / 60_000} мин скользящие, потолок ${SESSION_CAP_MS / 60_000} мин. ${tail}`;
      }
      case "batch-approve": {
        const row = this.db.prepare(`SELECT * FROM batches WHERE id = ? AND used_at IS NULL`).get(String(a.batchId)) as Raw | undefined;
        if (!row || String(row.set_hash) !== String(a.setHash)) throw new GuardError("not_found", "no such list (or it does not match the hash)");
        const items = JSON.parse(String(row.items)) as Array<{ kind: string; label: string }>;
        return `Одобрить пакетом ${items.length} ${items.length === 1 ? "элемент" : "элементов"} одним касанием (список зафиксирован у сторожа, хеш ${String(a.setHash).slice(0, 12)}…): ${items.slice(0, 8).map((i) => i.label).join("; ")}${items.length > 8 ? ` и ещё ${items.length - 8}` : ""}`;
      }
      case "open-window":
        return `Открыть окно доверия для плагина «${String(a.pluginId)}» на ${String(a.minutes)} мин${a.scope === "tree" ? " (охват: весь тред со всеми сабтредами)" : a.scope === "thread" ? " (охват: только этот тред)" : ""}${a.alarm === true ? ": ВНИМАНИЕ — в настройках агентов открыта критичная тревога, агент мог быть подменён; окно пропустит любые версии этого плагина без касания" : ": любые версии этого плагина будут загружаться без касания"}`;
      case "policy": {
        const cur = this.policy();
        const parts = Object.entries(a.patch as Record<string, unknown>).map(([k, v]) => `${k}: ${String(cur[k as keyof Policy])} → ${String(v)}`);
        return `Изменить политику окон доверия: ${parts.join(", ") || "без изменений"}`;
      }
      case "trust-mode": {
        const names: Record<TrustMode, string> = { simple: "Простой", detailed: "Подробный", strict: "Строгий" };
        return `Сменить режим доверия: «${names[this.trustMode()]}» → «${names[a.mode as TrustMode]}»${MODE_RANK[a.mode as TrustMode] < MODE_RANK[this.trustMode()] ? " (слабее: больше версий будет проходить без вопросов)" : ""}`;
      }
      case "sources-add":
        return `Добавить в «мои источники»: ${(a.entries as string[]).join(", ")}. Новые версии плагинов оттуда будут проходить без вопросов, если права те же, что у одобренной версии из того же источника, и нет жёстких флагов`;
      case "agents-accept": {
        if (this.agents === null) throw new GuardError("invalid", "the agent watch is not configured at this guard");
        const rows = this.openDrifts(a.ids as number[]);
        this.criticalAlone(rows);
        const by = (c: string): number => rows.filter((r) => String(r.class) === c).length;
        const first = rows.filter((r) => Number(r.initial) === 1).length;
        const list = rows.slice(0, 5).map((r) => `${String(r.path)} (${String(r.change)}, ${String(r.class)})`).join("; ");
        return `${first === rows.length ? "Первый эталон: принять всё как есть — " : ""}Принять в эталон наблюдателя за конфигурациями и памятью агентов ${rows.length} расхождений (критичных ${by("critical")}, инструкций ${by("instructions")}, прочих ${by("other")}): ${list}${rows.length > 5 ? ` и ещё ${rows.length - 5}` : ""}`;
      }
      case "agents-keep-part": {
        const { part, path } = this.partOf(Number(a.id), String(a.partId), String(a.fileSha));
        return `Оставить в настройках агента (${path}): ${this.partSentence(part)}. Это войдёт в одобренные настройки; остальное в файле решается отдельно${a.danger === true ? ". Это делает агента опаснее: нужно свежее касание" : ""}`;
      }
      case "agents-rollback-part": {
        const { part, path } = this.partOf(Number(a.id), String(a.partId), String(a.fileSha));
        return `Вернуть в настройках агента (${path}): ${this.partSentence(part)}. Это ослабляет агента (${rollbackDanger(part) ?? "?"}): нужно свежее касание`;
      }
      case "agents-revoke-kept": {
        const k = this.db.prepare(`SELECT * FROM agent_kept WHERE id = ? AND revoked_at IS NULL`).get(Number(a.id)) as Raw | undefined;
        if (!k) throw new GuardError("not_found", `no kept change #${String(a.id)}`);
        const part = JSON.parse(String(k.part)) as JsonPart;
        return `Отозвать оставленное в настройках агента (${String(k.path)}): ${this.partSentence(part)}. Отзыв ослабляет агента (${rollbackDanger(part) ?? "?"}): нужно свежее касание`;
      }
      case "agents-restore": {
        if (this.agents === null) throw new GuardError("invalid", "the agent watch is not configured at this guard");
        const [r] = this.openDrifts([Number(a.id)]);
        const plan = this.restorePlan(r!);
        if (!plan.ok) throw new GuardError("no_restore", plan.reason);
        return `Вернуть настройки агента как было: ${String(r!.path)} — ${plan.action === "delete" ? "файл будет удалён (в одобренных настройках его нет)" : plan.action === "json" ? `в общем файле состояния будут возвращены только разделы MCP-серверов (${plan.ops!.length}) в том виде, в каком вы их одобряли; остальное в файле не трогается` : `файл будет записан ровно в том виде, в каком вы его одобряли (хеш ${plan.sha.slice(0, 16)}…)`}. Содержимое берёт сам сторож из своих одобренных настроек; сразу после отката он просмотрит файл заново`;
      }
      case "touch":
        if (a.purpose === SETUP_CHECK_PURPOSE) return "Проверка касания при настройке: ничего не одобряется и не меняется, в журнал сторожа ляжет запись «касание сработало»";
        return `Подтвердить действие плагина secure-bb: ${String(a.purpose)}`;
      default:
        return `Подтвердить действие плагина secure-bb: ${String(a.purpose)}`;
    }
  }
}
