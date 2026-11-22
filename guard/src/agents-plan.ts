// What the guard knows about putting an agent's file back: the open differences, the plan of a restore, the parts of a settings file and what each part says.
// Reads only (no touch, no write): it sits below guard-actions.ts because describing and checking an action needs these answers; doing it is agents-apply.ts.
import { sep } from "node:path";
import { sha256 } from "./passkey.ts";
import { JSON_FILE, watchedRel, type JsonKey } from "./restore.ts";
import { prettyStableJson } from "./agents-scan.ts";
import { partDanger, shownValue, splitSettings, viewPart, type JsonPart, type PartView } from "./json-parts.ts";
import { GuardError, sha256hex, MAX_ACCEPT_IDS, type Raw, intOf, type JsonOp, type RestorePlan } from "./guard-types.ts";
import { GuardBase } from "./guard-base.ts";

export class AgentsPlanGuard extends GuardBase {
  protected agentIds(v: unknown): number[] {
    if (!Array.isArray(v) || v.length === 0 || v.length > MAX_ACCEPT_IDS) throw new GuardError("invalid", `ids is a list of 1..${MAX_ACCEPT_IDS} difference ids`);
    return [...new Set(v.map((x) => intOf(x, "id", 1, Number.MAX_SAFE_INTEGER)))].sort((a, b) => a - b);
  }
  /** The open differences with these ids; a missing one is not_found, one that is no longer open (superseded by a newer change, accepted) a conflict. */
  protected openDrifts(ids: number[]): Raw[] {
    const rows: Raw[] = [];
    for (const id of ids) {
      const r = this.db.prepare(`SELECT * FROM agent_drifts WHERE id = ?`).get(id) as Raw | undefined;
      if (!r) throw new GuardError("not_found", `no difference #${id}`);
      if (String(r.status) !== "open") throw new GuardError("conflict", `difference #${id} is already ${String(r.status)}${String(r.status) === "superseded" ? " (the file changed again: look at the new one)" : ""}`);
      rows.push(r);
    }
    return rows;
  }
  /**
   * A critical difference (bypassPermissions, Bash(*), an MCP server, a hook, a *_BASE_URL…) is accepted ALONE: never in one call with another
   * difference, so that "select all" cannot carry it in. It is also never covered by a session (`agents-accept` is not a routine action),
   * so every critical one takes its own fresh touch whose description names exactly it.
   */
  protected criticalAlone(rows: Raw[]): void {
    if (rows.length > 1 && rows.some((r) => String(r.class) === "critical")) throw new GuardError("invalid", "a critical difference is accepted on its own, with its own fresh touch: not together with others");
  }
  /** What putting this difference back means, from the baseline; or why it cannot be done. */
  /**
   * `.claude.json` is Claude Code's own state file, rewritten all the time: only the sections the watch looks at (the MCP servers, top-level and per
   * project) are put back, each by its own key; the rest of the file is not touched. The values come from the baseline's view of the file.
   */
  protected jsonPlan(d: Raw, path: string): RestorePlan {
    if (String(d.change) === "removed") return { ok: false, reason: "общий файл состояния агента (.claude.json) целиком не создаётся: вернуть можно только вручную" };
    // A file that appeared (nothing was approved): what is put back is "no MCP servers" — the same helper operation as for a changed file. The rest of the file
    // (Claude Code's own state) is not touched, and the file itself is neither created nor deleted by the helper.
    const added = String(d.change) === "added";
    const b = added ? undefined : (this.db.prepare(`SELECT * FROM agent_baseline WHERE path = ?`).get(path) as Raw | undefined);
    const base = added ? "{}" : ((b?.content as string | null | undefined) ?? null);
    if (!added && (!b || base === null || sha256hex(base) !== String(b.sha256))) return { ok: false, reason: "эталон разделов MCP этого файла не сохранён: вернуть можно только вручную" };
    const view = (t: string | null): { mcp: unknown; projects: Record<string, unknown> } | null => {
      try {
        const o = t === null ? null : (JSON.parse(t) as { mcpServers?: unknown; projects?: Record<string, { mcpServers?: unknown }> });
        if (typeof o !== "object" || o === null) return null;
        const projects: Record<string, unknown> = {};
        for (const [dir, p] of Object.entries(o.projects ?? {})) projects[dir] = p?.mcpServers;
        return { mcp: o.mcpServers ?? {}, projects };
      } catch {
        return null;
      }
    };
    const was = view(base);
    const now = view((d.new_content as string | null) ?? null);
    if (was === null || now === null) return { ok: false, reason: "файл не разобран как JSON: вернуть можно только вручную" };
    const isEmpty = (v: unknown): boolean => v === undefined || (typeof v === "object" && v !== null && Object.keys(v).length === 0);
    const ops: JsonOp[] = [];
    const add = (key: JsonKey, want: unknown, have: unknown): void => {
      if (prettyStableJson(want ?? {}) === prettyStableJson(have ?? {})) return;
      if (isEmpty(want)) ops.push({ key, value: null, sha: "0".repeat(64) });
      else ops.push({ key, value: want as Record<string, unknown>, sha: sha256hex(JSON.stringify(want)) });
    };
    add(["mcpServers"], was.mcp, now.mcp);
    for (const dir of new Set([...Object.keys(was.projects), ...Object.keys(now.projects)])) add(["projects", dir, "mcpServers"], was.projects[dir], now.projects[dir]);
    if (ops.length === 0) return { ok: false, reason: "в разделах MCP расхождения не видно (изменилась другая часть файла): вернуть можно только вручную" };
    if (ops.length > 50) return { ok: false, reason: "слишком много разделов для отката (больше 50): вернуть можно только вручную" };
    return { ok: true, action: "json", content: null, sha: added ? "0".repeat(64) : String(b!.sha256), ops };
  }
  protected restorePlan(d: Raw): RestorePlan {
    if (this.agents === null || this.agents.restore === undefined) return { ok: false, reason: "помощник отката не настроен у сторожа: вернуть файл можно только вручную" };
    const home = this.agents.home.replace(/(.)\/+$/, "$1");
    const path = String(d.path);
    if (!path.startsWith(home + sep)) return { ok: false, reason: "файл лежит вне домашнего каталога агентов: помощник сюда не пишет, вернуть можно только вручную" };
    const rel = path.slice(home.length + 1).split(sep).join("/");
    if (rel === JSON_FILE) return this.jsonPlan(d, path);
    if (!watchedRel(rel)) return { ok: false, reason: "этот файл помощник не возвращает: вернуть можно только вручную" };
    if (String(d.change) === "added") return { ok: true, action: "delete", content: null, sha: String(d.new_sha ?? "0".repeat(64)) };
    const b = this.db.prepare(`SELECT * FROM agent_baseline WHERE path = ?`).get(path) as Raw | undefined;
    if (!b) return { ok: false, reason: "в одобренных настройках нет эталона этого файла: возвращать нечего" };
    const content = (b.content as string | null) ?? null;
    if (content === null) return { ok: false, reason: "эталонного содержимого нет: файл больше лимита хранения (256 КБ), сторож помнит только его хеш. Вернуть можно только вручную" };
    if (sha256hex(content) !== String(b.sha256)) return { ok: false, reason: "эталон хранит не файл целиком, а его вид или ссылку: точно воспроизвести его нельзя, вернуть можно только вручную" };
    return { ok: true, action: "write", content, sha: String(b.sha256) };
  }
  // ---- parts of a settings file: «Оставить» (mine) and «Вернуть» (theirs) --------------------------------------------------------------
  /** The parts of an open difference of a settings file, from the guard's own baseline and the file it read; null when it cannot be split. */
  protected partsOf(d: Raw): JsonPart[] | null {
    if (String(d.kind) !== "claude-settings" || String(d.status) !== "open" || String(d.change) === "removed") return null;
    const next = (d.new_content as string | null | undefined) ?? null;
    if (next === null) return null;
    const base = this.baselineText(d);
    return base === undefined ? null : splitSettings(base, next);
  }
  /** The text the owner approved for this file: null for a file that is new (nothing was approved); undefined: there is a baseline, but it is not whole (too large, or not the file's text). */
  protected baselineText(d: Raw): string | null | undefined {
    if (String(d.change) === "added") return null;
    const b = this.db.prepare(`SELECT * FROM agent_baseline WHERE path = ?`).get(String(d.path)) as Raw | undefined;
    const base = (b?.content as string | null | undefined) ?? null;
    return b && base !== null && sha256hex(base) === String(b.sha256) ? base : undefined;
  }
  /**
   * One part of one open difference, found by the id the page named; the page's `fileSha` (the first 16 digits of the hash it was shown) must be the file's
   * now, otherwise the file changed between the showing and the action: a conflict, the page draws again.
   */
  protected partOf(id: number, partId: string, fileSha: string): { drift: Raw; part: JsonPart; parts: JsonPart[]; danger: string | null; path: string } {
    if (this.agents === null) throw new GuardError("invalid", "the agent watch is not configured at this guard");
    const [d] = this.openDrifts([id]);
    if (d!.new_sha === null || String(d!.new_sha).slice(0, 16) !== fileSha) throw new GuardError("conflict", "the file changed since it was shown: look again");
    const parts = this.partsOf(d!);
    if (parts === null) throw new GuardError("no_restore", "этот файл нельзя разобрать по частям: вернуть или принять можно только целиком");
    const part = parts.find((p) => p.id === partId);
    if (!part) throw new GuardError("conflict", "this part is not in the difference any more: look again");
    return { drift: d!, part, parts, danger: partDanger(part), path: String(d!.path) };
  }
  protected partSentence(p: JsonPart): string {
    const at = p.path.join(".");
    switch (p.kind) {
      case "elem-added":
        return `добавлено в ${at}: ${shownValue(p.path, p.elem)}`;
      case "elem-removed":
        return `убрано из ${at}: ${shownValue(p.path, p.elem)}`;
      case "key-added":
        return `${at} задан: ${shownValue(p.path, p.after)}`;
      case "key-removed":
        return `${at} убран (было ${shownValue(p.path, p.before)})`;
      case "key-changed":
        return `${at}: было ${shownValue(p.path, p.before)}, стало ${shownValue(p.path, p.after)}`;
    }
  }
  /** The parts the owner kept and has not taken back: the list of exceptions. Values are for the screen (secrets hidden). */
  protected keptParts(): Array<{ id: number; path: string; rel: string; keptAt: number; danger: string | null; part: PartView }> {
    const rows = this.db.prepare(`SELECT * FROM agent_kept WHERE revoked_at IS NULL ORDER BY id DESC LIMIT 200`).all() as Raw[];
    return rows.map((r) => ({ id: Number(r.id), path: String(r.path), rel: String(r.rel), keptAt: Number(r.kept_at), danger: (r.danger as string | null) ?? null, part: viewPart(JSON.parse(String(r.part)) as JsonPart) }));
  }
}
