// The decisions that used to sit inside the page's components, now plain functions: which alarms there are, what the extended queue card shows, what the card of a version says.
import { describe, expect, it } from "vitest";
import { pluginPinText, queueFacts, queueLabel, queueSourceLine, queueStatusWord, reviewView, scanHeadText, skillCapsLine, skillFindingsShown } from "../src/cardview";
import { agentsFacts, OVERLAY_COLLAPSE_KEY, overlayView, pageAlarms } from "../src/pageview";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
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
    expect(agentsFacts(ovOf({ agents: { state: { drifts: [], alarms: [] } } })).tab).toBe("settings");
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
  it("a version the guard did not read is told as «not read», with its reason; only real blocks are «ведёт себя как вредоносный»", () => {
    const ux = { why: null, chain: [], level: "unknown" as const, entry: null, sourceLabel: "github.com/o/chime" };
    const unread = reviewView({ q: q({ reasonKind: "other", blocks: null, reason: "каталог версии вне каталогов плагинов ядра" } as Partial<QueueRow>), found: found("network"), ux, flowDowngrade: false });
    expect(unread.red).toBe(true);
    expect(unread.text.title).toBe("Сторож не смог сам прочитать эту версию");
    expect(unread.text.line).toContain("Причина: каталог версии вне каталогов плагинов ядра.");
    expect(`${unread.text.title} ${unread.text.line}`).not.toMatch(/вредонос/);
    const block = reviewView({ q: q({ reasonKind: "block", blocks: ["decode-eval a.js:1"], reason: "жёсткий флаг: decode-eval a.js:1" } as Partial<QueueRow>), found: found("network"), ux, flowDowngrade: false });
    expect(block.red).toBe(true);
    expect(block.text.title).toMatch(/^Остановлено: /);
    expect(block.text.title).not.toMatch(/не смог сам прочитать/);
    const clean = reviewView({ q: q({ reasonKind: "unknown-source", blocks: [], reason: "неизвестный источник" } as Partial<QueueRow>), found: found("network"), ux, flowDowngrade: false });
    expect(clean.red).toBe(false);
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

describe("the strip that floats over all of bb", () => {
  const gap = (at: number, minutes: number) => ({ from: at - minutes * 60_000, to: at, ms: minutes * 60_000, at, mode: "guard" as const, cause: "unknown" as const, stopped: false, safeMode: false });
  const ov = (gaps: Array<ReturnType<typeof gap>>, over: Record<string, unknown> = {}): Overview =>
    ovOf({ guard: { connected: true, maintenance: [] }, windows: [], watch: { drifts: [], baselineAt: 1, windows: [] }, alive: { gaps, safeMode: false, safeModeSeen: false, gapsAckedAt: null, reviewedAts: [], coreHolds: false }, ...over });

  it("the alarm about a pause is ONE line: the count and the minutes, no paragraph and no list of what did not work", () => {
    const v = overlayView(ov([gap(2_000_000, 13), gap(1_000_000, 3)]), null);
    expect(v.alarmLine).toBe("Тревога: защита не работала 2 раза (3 и 13 мин)");
    expect(v.alarmLine).not.toMatch(/Не работало|Сторож в это время|страница, коды|наблюдение за настройками/);
    expect(v.alarmLine!.length).toBeLessThan(80);
    expect(overlayView(ov([gap(1_000_000, 13)]), null).alarmLine).toBe("Тревога: защита не работала 13 мин");
    expect(overlayView(ov([gap(3, 3), gap(2, 5), gap(1, 13)]), null).alarmLine).toBe("Тревога: защита не работала 3 раза (13, 5 и 3 мин)");
    expect(overlayView(ov([]), null).alarmLine).toBeNull();
    expect(overlayView(ov([], { alive: { gaps: [], safeMode: true, safeModeSeen: true, gapsAckedAt: null, reviewedAts: [], coreHolds: false } }), null).alarmLine).toBe("Тревога: включён safe-mode bb");
  });
  it("folding is remembered against the set of the pauses: the same alarm stays folded, a NEW one unfolds it", () => {
    const first = overlayView(ov([gap(1_000_000, 3)]), null);
    expect(first.collapsed).toBe(false);
    expect(overlayView(ov([gap(1_000_000, 3)]), first.alarmKey).collapsed).toBe(true);
    const next = overlayView(ov([gap(2_000_000, 5), gap(1_000_000, 3)]), first.alarmKey);
    expect(next.alarmKey).not.toBe(first.alarmKey);
    expect(next.collapsed).toBe(false);
    // folding is not a confirmation: the alarm is still an alarm for the page
    expect(pageAlarms(ov([gap(1_000_000, 3)]), true).some((a) => /не работал/.test(a.text))).toBe(true);
  });
  it("an open trust window is shown whatever the alarm does: folded or not, the window is there", () => {
    const withWindow = ov([gap(1_000_000, 3)], { windows: [{ id: 1 }] });
    const key = overlayView(withWindow, null).alarmKey;
    const v = overlayView(withWindow, key);
    expect(v.collapsed).toBe(true);
    expect(v.windows).toBe(true);
    expect(v.show).toBe(true);
    expect(overlayView(ov([], { watch: { drifts: [], baselineAt: 1, windows: [{ id: 2 }] } }), null)).toMatchObject({ windows: true, alarmLine: null, show: true });
  });
  it("nothing to show: no alarm, no window", () => {
    expect(overlayView(ov([]), null).show).toBe(false);
  });
  it("the strip never draws the full alarm (that is the page's), keeps the folded state in localStorage under one key, and tries before it touches it", () => {
    const src = readFileSync(fileURLToPath(new URL("../app/windows.tsx", import.meta.url)), "utf8");
    const strip = src.slice(src.indexOf("export function WindowOverlay"));
    expect(strip).not.toContain("<AliveAlarm");
    expect(strip).not.toMatch(/notWorking|works/);
    expect(strip).toContain("overlayView(");
    expect(OVERLAY_COLLAPSE_KEY).toBe("sbb-overlay-collapsed");
    expect(src).toMatch(/try \{\s*return window\.localStorage\.getItem\(OVERLAY_COLLAPSE_KEY\)/);
  });
});
