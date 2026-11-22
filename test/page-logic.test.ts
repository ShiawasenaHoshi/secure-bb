// The decisions that used to sit inside the page's components, now plain functions: which alarms there are, what the extended queue card shows, what the card of a version says.
import { describe, expect, it } from "vitest";
import { pluginPinText, queueFacts, queueLabel, queueSourceLine, queueStatusWord, reviewView, scanHeadText, skillCapsLine, skillFindingsShown } from "../src/cardview";
import { agentsFacts, pageAlarms } from "../src/pageview";
import type { Overview } from "../src/overview";
import type { QueueRow } from "../src/store";

const ovOf = (over: Record<string, unknown> = {}): Overview =>
  ({ now: 1000, journal: { ok: true }, alive: { gaps: [], safeMode: false, gapsAckedAt: 0, coreHolds: true }, watch: { drifts: [], baselineAt: 1 }, guard: undefined, agents: undefined, ...over }) as unknown as Overview;

describe("the alarms of the page", () => {
  it("none when everything is in order and the second factor is set up", () => {
    expect(pageAlarms(ovOf(), true)).toEqual([]);
  });
  it("each real alarm, in the order the header reads them; the missing second factor is one of them", () => {
    const ov = ovOf({ journal: { ok: false }, watch: { drifts: [{ status: "open" }], baselineAt: 1 }, guard: { connected: true, journal: { valid: false }, troubleshootUntil: 5000 } });
    expect(pageAlarms(ov, false).map((a) => a.text)).toEqual(["Журнал решений нарушен", "Журнал сторожа нарушен", "Настройки bb изменились", "Второй фактор не настроен", "Включён режим отладки сторожа: он пропускает всё"]);
  });
  it("the agents' settings: critical changes and unreadable files, with the tab they stand on", () => {
    const agents = { state: { drifts: [{ class: "critical", initial: false }, { class: "critical", initial: true }, { class: "minor", initial: false }], alarms: [{ path: "/x" }] } };
    expect(agentsFacts(ovOf({ agents }))).toMatchObject({ critical: 1, alarms: 1, tab: "status" });
    const a = pageAlarms(ovOf({ agents }), true).find((x) => x.anchor === "sbb-agents")!;
    expect(a.text).toBe("Настройки агентов: критичных изменений — 1, файлов не прочитать — 1");
    expect(a.weight).toBe(2);
    expect(agentsFacts(ovOf({ agents: { state: { drifts: [], alarms: [] } } })).tab).toBe("more");
  });
});

describe("the extended queue card", () => {
  const q = { id: 4, status: "held", reason: "каталог доступен на запись другим пользователям", sourceKind: "git", source: "github.com/o/r", threadId: "T1", kind: "proposal", contentHash: null };
  it("facts, words and the label", () => {
    expect(queueFacts(q, true)).toEqual({ held: true, blocked: true, unsafeDir: true });
    expect(queueFacts({ status: "approved", reason: null }, false)).toEqual({ held: false, blocked: false, unsafeDir: false });
    expect([queueStatusWord("held", true), queueStatusWord("held", false), queueStatusWord("approved", false), queueStatusWord("stale", false), queueStatusWord("dismissed", false)]).toEqual(["заблокировано", "держится", "одобрено", "устарело", "отклонено"]);
    expect(queueSourceLine(q)).toBe("git: github.com/o/r · из чата T1 · предложен агентом, окно было закрыто");
    expect(queueSourceLine({ ...q, kind: "afterfact", threadId: null, contentHash: "h" })).toBe("git: github.com/o/r · выключен после загрузки (его код уже выполнялся)");
    expect([queueLabel(4), queueLabel(-3)]).toEqual(["#4", "предложение 3"]);
  });
});

describe("the card of a waiting version", () => {
  const q = (over: Partial<QueueRow> = {}): QueueRow => ({ id: 1, kind: "hook", contentHash: "h", pluginId: "chime", version: "0.1.0", source: "github.com/o/chime", sourceKind: "git", rootDir: null, gitCommit: null, npmIntegrity: null, trigger: null, threadId: null, proposalId: null, status: "held", reason: "неизвестный источник", firstSeen: 1, lastSeen: 1, ...over }) as QueueRow;
  const found = (kind: string) => ({ findings: [], capabilities: [{ kind, detail: [], sites: [] }], stats: {} }) as never;
  it("yellow for an unknown source: «Нужна проверка», approve offered, the sentence of the yellow text", () => {
    const v = reviewView({ q: q(), found: found("network"), ux: { why: null, chain: [], level: "unknown", entry: null, sourceLabel: "github.com/o/chime" }, flowDowngrade: false });
    expect(v).toMatchObject({ red: false, level: "check", noRecord: false, mismatch: false, canApprove: true, approveWhat: "Разрешить chime 0.1.0", allowedWhat: "chime 0.1.0 разрешён и включён" });
    expect(v.text.line).toMatch(/Плагин из места, которое вы раньше не отмечали/);
  });
  it("red for files that did not match: no approve, the words of the mismatch", () => {
    const v = reviewView({ q: q({ reason: "каталог плагина не совпал с хешем запроса" }), found: found("ui"), ux: undefined, flowDowngrade: false });
    expect(v).toMatchObject({ red: true, mismatch: true, canApprove: false, level: "danger" });
    expect(v.text.title).toMatch(/не совпал/);
  });
  it("a version the guard has no record of cannot be approved here", () => {
    const v = reviewView({ q: q({ kind: "afterfact", contentHash: null }), found: undefined, ux: undefined, flowDowngrade: false });
    expect(v).toMatchObject({ noRecord: true, canApprove: false });
  });
  it("the unsafe directory is a fact of the card", () => {
    expect(reviewView({ q: q({ reason: "каталог доступен на запись другим пользователям" }), found: undefined, ux: undefined, flowDowngrade: false }).unsafeDir).toBe(true);
  });
});

describe("the small lines of the rows", () => {
  it("a plugin's pin, a skill's findings and capabilities, the head of a scan", () => {
    expect(pluginPinText({ pin: { version: "1.0.0" }, frozenPin: false, unreviewedBaseline: false }, "вы, кодом, 14:14")).toBe("пин: 1.0.0 (вы, кодом, 14:14)");
    expect(pluginPinText({ pin: { version: "1.0.0" }, frozenPin: true, unreviewedBaseline: false }, "x")).toBe("закреплена при заморозке: 1.0.0 (x)");
    expect(pluginPinText({ pin: null, frozenPin: false, unreviewedBaseline: true }, null)).toBe("стоял до secure-bb, не проверялся");
    expect(pluginPinText({ pin: null, frozenPin: false, unreviewedBaseline: false }, null)).toBe("не одобрен");
    expect(skillFindingsShown([{ severity: "info" }, ...Array.from({ length: 15 }, () => ({ severity: "block" }))])).toHaveLength(12);
    expect(skillCapsLine([])).toBeNull();
    expect(skillCapsLine([{ kind: "network", detail: ["a", "b", "c", "d"] }, { kind: "fs", detail: [] }])).toBe("Возможности скриптов: network (a, b, c); fs");
    const at = (ms: number) => `t${ms}`;
    const base = { startedAt: 1, finishedAt: 2, models: [{ status: "clean", label: "A" }, { status: "unavailable", label: "B" }] };
    expect(scanHeadText({ ...base, status: "running" }, at)).toBe("идёт…");
    expect(scanHeadText({ ...base, status: "clean" }, at)).toBe("чисто (t2, A)");
    expect(scanHeadText({ ...base, status: "suspect" }, at)).toBe("ПОДОЗРЕНИЕ (t2)");
    expect(scanHeadText({ ...base, status: "failed", note: "нет сети" }, at)).toBe("недоступен: нет сети");
  });
});
