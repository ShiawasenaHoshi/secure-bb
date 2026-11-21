// Fixes after the pilot with AI testers (a non-technical person and a power user): the page's decisions as pure functions.
import { describe, expect, it } from "vitest";
import {
  SESSION_LINE, emphasize, TECHNICAL_WORDS, actionLabel, agentAcceptProblem, agentsSectionTab, awayText, awaySeenMark, awaySince, capabilityPhrase, capabilitySegments,
  classifyAway, compareVersions, criticalAcceptTitle, criticalMeanings, decisionOf, deferKey, deleteConfirmText, deletedNote, groupAway, isCriticalDrift,
  launchProblem, moreVersionsText, pageStatus, planCards, proofHint, reconcileSelection, sameData, selectableDriftIds, sessionText, setFold, toggleId,
  trustButton, windowAvailability,
} from "../src/ux.ts";
import type { AwayEvent, Decisions, HeldLike } from "../src/ux.ts";

const T0 = 1_000_000;
const none: Decisions = { deferred: [], kept: [] };
const held = (id: number, pluginId: string, version: string, hash: string | null = `h${id}`): HeldLike => ({ id, pluginId, version, contentHash: hash });

describe("2. rights are concrete", () => {
  const env = (...detail: string[]) => capabilityPhrase({ kind: "env", detail });
  it("env:HOME and env:* read differently; «все» is the red word of env:*", () => {
    expect(env("HOME")).toBe("узнать путь к вашей домашней папке (только где она лежит, не её содержимое)");
    expect(env("*")).toBe("прочитать все переменные окружения (там бывают пароли и токены)");
    expect(env("HOME")).not.toBe(env("*"));
    expect(env("HOME")).not.toMatch(/пароли|токены|все/);
    expect(capabilitySegments({ kind: "env", detail: ["*"] }).filter((s) => s.red).map((s) => s.text)).toEqual(["все"]);
    expect(capabilitySegments({ kind: "env", detail: ["HOME"] }).some((s) => s.red)).toBe(false);
  });
  it("a name that looks like a secret says so; an ordinary unknown one is just named; no names means all", () => {
    expect(env("GITHUB_TOKEN")).toBe("прочитать «GITHUB_TOKEN» (там обычно пароль или ключ)");
    expect(env("MY_FLAG")).toBe("прочитать переменную окружения «MY_FLAG»");
    expect(env()).toContain("все");
    expect(env("HOME", "*")).toContain("все");
    expect(env("HOME", "USER")).toBe("узнать путь к вашей домашней папке (только где она лежит, не её содержимое); узнать имя вашего пользователя");
  });
  it("the network to a named host is not «в интернет вообще»", () => {
    const one = capabilityPhrase({ kind: "network", detail: ["host:telemetry.example", "module:node:https"] });
    const any = capabilityPhrase({ kind: "network", detail: ["module:node:https"] });
    expect(one).toContain("telemetry.example");
    expect(one).not.toContain("любые");
    expect(any).toContain("любые адреса");
    expect(one).not.toBe(any);
  });
  it("an ordinary plugin and the thief no longer read the same", () => {
    const hello = [capabilityPhrase({ kind: "network", detail: ["host:telemetry.example"] }), env("HOME")].join("; ");
    const thief = [capabilityPhrase({ kind: "network", detail: [] }), env("*")].join("; ");
    expect(hello).not.toBe(thief);
    expect(hello).not.toMatch(/пароли|токены/);
    expect(thief).toMatch(/все переменные/);
  });
  it("a card's whole line marks «все» in red too; without it nothing is red", () => {
    const line = `Он сможет: ${env("*")}; ${env("HOME")}.`;
    expect(emphasize(line).filter((x) => x.red).map((x) => x.text)).toEqual(["все"]);
    expect(emphasize(line).map((x) => x.text).join("")).toBe(line);
    expect(emphasize(`Он сможет: ${env("HOME")}.`).some((x) => x.red)).toBe(false);
  });
  it("no technical words in them", () => {
    for (const c of [{ kind: "env", detail: ["*"] }, { kind: "env", detail: ["HOME"] }, { kind: "network", detail: [] }]) expect(capabilityPhrase(c)).not.toMatch(TECHNICAL_WORDS);
  });
});

describe("3. one card per plugin", () => {
  const entries = [held(1, "hello", "0.0.4"), held(2, "hello", "0.0.9"), held(3, "other", "1.0.0")];
  it("the latest version is shown, the other waits under it", () => {
    const p = planCards(entries, none);
    expect(p.active.map((c) => [c.pluginId, c.shown.version, c.others.map((o) => o.version)])).toEqual([["hello", "0.0.9", ["0.0.4"]], ["other", "1.0.0", []]]);
    expect(p.later).toEqual([]);
  });
  it("versions compare by number, not as text; ties go to the newer entry", () => {
    expect(compareVersions("0.0.10", "0.0.9")).toBeGreaterThan(0);
    expect(compareVersions("1.2", "1.2.0")).toBe(0);
    expect(compareVersions("v2.0.0", "1.9.9")).toBeGreaterThan(0);
    expect(planCards([held(5, "p", "1.0.0"), held(6, "p", "1.0.0"), held(4, "p", "0.9.0")], none).active[0]!.shown.id).toBe(6);
    expect(planCards([held(1, "p", "0.0.9"), held(2, "p", "0.0.10")], none).active[0]!.shown.version).toBe("0.0.10");
  });
  it("«ещё N версий ждут»", () => {
    expect(moreVersionsText(1)).toBe("ещё 1 версия ждёт");
    expect(moreVersionsText(2)).toBe("ещё 2 версии ждут");
    expect(moreVersionsText(5)).toBe("ещё 5 версий ждут");
  });
  it("the actions name the version they are about", () => {
    expect(actionLabel("Разрешить", "hello", "0.0.9")).toBe("Разрешить hello 0.0.9");
  });
  it("a plugin whose open version was handled keeps one card from what is left", () => {
    const p = planCards(entries, { deferred: [deferKey("hello", "h2", 2)], kept: [] });
    const hello = [...p.active, ...p.later].filter((c) => c.pluginId === "hello");
    expect(hello).toHaveLength(1);
    expect(hello[0]!.shown.version).toBe("0.0.4"); // the open one is shown; the deferred one waits under it
    expect(hello[0]!.others.map((o) => o.version)).toEqual(["0.0.9"]);
  });
});

describe("6. «Оставить в карантине» is a decision", () => {
  const red = held(7, "sbb-test-hello", "0.0.9");
  const keptKey = deferKey("sbb-test-hello", "h7", 7);
  it("a kept entry leaves the cards and is not counted as unresolved", () => {
    const p = planCards([red, held(8, "evil-env", "1.0.0")], { deferred: [], kept: [keptKey] });
    expect(p.kept.map((e) => e.id)).toEqual([7]);
    expect(p.unresolved.map((e) => e.id)).toEqual([8]);
    expect(p.active.map((c) => c.pluginId)).toEqual(["evil-env"]);
  });
  it("the red status counts only the unresolved: with the red one kept it is not «Остановлено»", () => {
    const ref = (e: HeldLike) => ({ anchor: `c${e.id}`, tab: "status" as const, text: e.pluginId });
    const before = planCards([red], none);
    expect(pageStatus({ guardDown: false, red: before.unresolved.map(ref), yellow: [], alarms: [] }).level).toBe("stopped");
    const after = planCards([red], { deferred: [], kept: [keptKey] });
    const s = pageStatus({ guardDown: false, red: after.unresolved.map(ref), yellow: [], alarms: [] });
    expect(s.level).toBe("ok");
    expect(s.count).toBe(0);
  });
  it("«Решить позже» is NOT a decision: the entry stays unresolved (and in the status)", () => {
    const p = planCards([red], { deferred: [keptKey], kept: [] });
    expect(p.unresolved).toHaveLength(1);
    expect(p.later).toHaveLength(1);
    expect(p.active).toHaveLength(0);
  });
});

describe("8. «Вы отложили» only after «Решить позже»", () => {
  it("by default nothing is deferred, so no folded list", () => {
    const p = planCards([held(1, "a", "1")], none);
    expect(p.later).toEqual([]);
    expect(decisionOf(held(1, "a", "1"), none)).toBe("open");
  });
  it("an old mark for the same code held again (another entry) does not count", () => {
    const old = { deferred: [deferKey("a", "same", 1)], kept: [] };
    expect(decisionOf(held(1, "a", "1", "same"), old)).toBe("deferred");
    expect(decisionOf(held(2, "a", "1", "same"), old)).toBe("open");
    expect(planCards([held(2, "a", "1", "same")], old).later).toEqual([]);
  });
  it("after the press the card is in the folded list", () => {
    const p = planCards([held(1, "a", "1")], { deferred: [deferKey("a", "h1", 1)], kept: [] });
    expect(p.later.map((c) => c.pluginId)).toEqual(["a"]);
  });
});

describe("7. «Удалить»", () => {
  it("asks first, names the plugin and version; says «Удалён» after", () => {
    expect(deleteConfirmText("sbb-test-hello", "0.0.9")).toBe("Удалить плагин sbb-test-hello 0.0.9? Чтобы вернуть, установите плагин снова");
    expect(deletedNote("sbb-test-hello", "0.0.9")).toBe("Удалён: плагин sbb-test-hello 0.0.9.");
  });
  it("the summary says «удалён», not «отклонена»", () => {
    const e = (kind: string): AwayEvent => ({ ts: T0 + 1, kind, pluginId: "evil-env", detail: null, from: "guard" });
    expect(classifyAway(e("dismissed"), true)).toBe("deleted");
    const g = groupAway([e("dismissed")], T0, true);
    expect(g[0]!.text).toMatch(/удалена/);
    expect(g[0]!.text).not.toMatch(/отклонен/);
    expect(awayText({ pluginId: "p", counts: { auto: 0, window: 0, approved: 0, held: 0, stopped: 0, rejected: 0, deleted: 3, alarm: 0 } })).toBe("3 версии p удалены");
  });
});

describe("9. trust window for a plugin from a folder", () => {
  it("is unavailable, says why, and what to do instead (own source: nothing to do)", () => {
    const w = windowAvailability({ threadId: null, queueId: 4, sourceKind: "path", level: "own" });
    expect(w.available).toBe(false);
    expect(w.note).toContain("из папки");
    expect(w.note).toContain("Ваш источник уже в доверенных: версии без новых прав проходят сами");
  });
  it("a folder that is not yet trusted points at «доверять источнику»", () => {
    const w = windowAvailability({ threadId: null, queueId: 4, sourceKind: "path", level: "unknown" });
    expect(w.note).toContain("Разрешить и доверять источнику");
  });
  it("from a thread it is available", () => {
    expect(windowAvailability({ threadId: "thr_1", queueId: 4, sourceKind: "git", level: "known" })).toEqual({ available: true, note: null });
    expect(windowAvailability({ threadId: "thr_1", queueId: -4, sourceKind: "git", level: "known" }).available).toBe(false);
  });
  it("the button that would do nothing is not active", () => {
    expect(trustButton({ entry: "path:/x", level: "own", queueId: 4 }).enabled).toBe(false);
    expect(trustButton({ entry: "path:/x", level: "own", queueId: 4 }).note).toContain("уже в доверенных");
    expect(trustButton({ entry: null, level: "unknown", queueId: 4 }).enabled).toBe(false);
    expect(trustButton({ entry: "path:/x", level: "unknown", queueId: -1 }).enabled).toBe(false);
    expect(trustButton({ entry: "path:/x", level: "unknown", queueId: 4 })).toEqual({ enabled: true, note: null });
  });
});

describe("10. allowed but did not start", () => {
  it("the core's error is shown with its message", () => {
    expect(launchProblem({ status: "error", statusDetail: "Cannot find module './x'" })).toBe("Разрешён, но упал при запуске: Cannot find module './x'");
  });
  it("no message from the core is said so; other statuses add nothing", () => {
    expect(launchProblem({ status: "error", statusDetail: null })).toBe("Разрешён, но упал при запуске: ядро не назвало причину");
    expect(launchProblem({ status: "active" })).toBeNull();
    expect(launchProblem({ status: "waiting" })).toBeNull();
  });
  it("a long message is cut", () => {
    expect(launchProblem({ status: "error", statusDetail: "x".repeat(900) })!.length).toBeLessThan(400);
  });
});

describe("11. «Пока вас не было»", () => {
  const ev = (ts: number, kind = "approved.touch"): AwayEvent => ({ ts, kind, pluginId: "p", detail: null, from: "guard" });
  it("after «Всё в порядке» it does not come back until there is a newer event, even when the journal's clock is ahead", () => {
    const now = T0 + 100;
    const events = [ev(T0 + 50), ev(T0 + 100_000)]; // the second is stamped ahead of the page's clock
    const mark = awaySeenMark(events, now);
    expect(mark).toBe(T0 + 100_000);
    expect(groupAway(events, mark, true)).toEqual([]);
    expect(groupAway([...events, ev(mark + 1)], mark, true)).toHaveLength(1);
  });
  it("with nothing ahead the mark is «now»", () => {
    expect(awaySeenMark([ev(5)], 100)).toBe(100);
    expect(awaySeenMark([], 100)).toBe(100);
  });
  it("«одобрили вы» is neutral: «одобрена»", () => {
    const t = (n: number) => awayText({ pluginId: "p", counts: { auto: 0, window: 0, approved: n, held: 0, stopped: 0, rejected: 0, deleted: 0, alarm: 0 } });
    expect(t(1)).toBe("1 версия p одобрена");
    expect(t(2)).toBe("2 версии p одобрены");
    expect(t(5)).toBe("5 версий p одобрено");
    expect(t(2)).not.toMatch(/вы/);
    expect(awaySince(String(T0), T0 + 5)).toBe(T0);
  });
});

describe("4. the code and the session", () => {
  it("the hint beside the field: the phone's app, or a finger when there is a key", () => {
    expect(proofHint({ hasKey: false, keyOnly: false })).toContain("6 цифр из приложения на телефоне (Google Authenticator и т. п.)");
    expect(proofHint({ hasKey: true, keyOnly: true })).toMatch(/Приложите палец/);
    expect(proofHint({ hasKey: true, keyOnly: false })).toMatch(/Приложите палец/);
    expect(proofHint({ hasKey: true, keyOnly: false })).toContain("6 цифр");
  });
  it("«Простой»: one line, details folded; no «токен» and no «хеш» anywhere", () => {
    const s = sessionText("simple", true);
    expect(s.line).toBe("Открыть на 15 минут, чтобы не вводить код каждый раз");
    expect(s.line).toBe(SESSION_LINE);
    expect(s.foldDetails).toBe(true);
    for (const mode of ["simple", "detailed", "strict", null] as const)
      for (const guard of [true, false]) {
        const t = sessionText(mode, guard);
        expect(`${t.line} ${t.details}`, `${mode}/${guard}`).not.toMatch(/токен|хеш|хэш|token|hash/i);
      }
    expect(sessionText("detailed", true).foldDetails).toBe(false);
  });
});

describe("1. critical agent changes are not accepted in a pack", () => {
  const drifts = [
    { id: 1, class: "critical", reasons: ['permissions.allow «Bash(*)»: Bash без ограничений'] },
    { id: 2, class: "critical", reasons: ["permissions.defaultMode: bypassPermissions"] },
    { id: 3, class: "instructions", reasons: [] },
    { id: 4, class: "other", reasons: ["файл удалён"] },
  ];
  it("«выбрать все» takes only the non-critical", () => {
    expect(selectableDriftIds(drifts)).toEqual([3, 4]);
    expect(isCriticalDrift(drifts[0]!)).toBe(true);
  });
  it("a selection never keeps a critical id, nor one that has gone", () => {
    expect(reconcileSelection([1, 3, 4, 99], drifts)).toEqual([3, 4]);
  });
  it("a critical id with any other id is a problem, before a code is spent; alone or non-critical together is fine", () => {
    expect(agentAcceptProblem([1, 3], drifts)).toMatch(/отдельно/);
    expect(agentAcceptProblem([1, 2], drifts)).toMatch(/отдельно/);
    expect(agentAcceptProblem([1], drifts)).toBeNull();
    expect(agentAcceptProblem([3, 4], drifts)).toBeNull();
  });
  it("each critical one is named by what it lets the agent do", () => {
    expect(criticalMeanings(drifts[0]!.reasons)).toEqual(["агент сможет выполнять любые команды без спроса"]);
    expect(criticalAcceptTitle(drifts[0]!.reasons)).toBe("Принимая это, вы разрешаете: агент сможет выполнять любые команды без спроса");
    expect(criticalMeanings(drifts[1]!.reasons)[0]).toContain("без вопросов к вам");
    expect(criticalMeanings(["MCP-сервер helper: новый"])[0]).toContain("helper");
    expect(criticalMeanings(["hooks: новые или изменённые (команды, которые агент запускает сам)"])[0]).toContain("хуки");
    expect(criticalMeanings(["env ANTHROPIC_BASE_URL: задан"])[0]).toContain("другой адрес");
    expect(criticalMeanings(["env HTTPS_PROXY: изменён"])[0]).toContain("прокси");
    expect(criticalMeanings(["что-то новое"])).toEqual(["что-то новое"]);
    expect(criticalMeanings(["permissions.allow «Bash(*)»: Bash без ограничений", "permissions.allow «Bash(:*)»: Bash без ограничений"])).toHaveLength(1);
  });
  it("the section is shown on «Статус» while something critical or an alarm waits", () => {
    expect(agentsSectionTab({ critical: 2, alarms: 0 })).toBe("status");
    expect(agentsSectionTab({ critical: 0, alarms: 1 })).toBe("status");
    expect(agentsSectionTab({ critical: 0, alarms: 0 })).toBe("more");
  });
});

describe("13/14. stable folds, selections and data", () => {
  it("a fold keeps its state by id; setting the same state changes nothing (same object)", () => {
    const a = setFold({}, "card-1", true);
    expect(a).toEqual({ "card-1": true });
    expect(setFold(a, "card-1", true)).toBe(a);
    expect(setFold(a, "card-2", true)).toEqual({ "card-1": true, "card-2": true });
    expect(setFold(a, "card-1", false)).toEqual({ "card-1": false });
  });
  it("a checkbox changes one id and nothing else; «выбрать все» then one click does not swap the others", () => {
    const all = selectableDriftIds([{ id: 3, class: "other" }, { id: 4, class: "other" }, { id: 5, class: "critical" }]);
    expect(toggleId(all, 3, false)).toEqual([4]);
    expect(toggleId(all, 4, true)).toBe(all);
    expect(toggleId([], 4, true)).toEqual([4]);
  });
  it("two overviews that differ only by the server's clock are the same: the page does not rebuild", () => {
    expect(sameData({ now: 1, queue: [{ id: 1 }] }, { now: 2, queue: [{ id: 1 }] })).toBe(true);
    expect(sameData({ now: 1, queue: [{ id: 1 }] }, { now: 2, queue: [{ id: 2 }] })).toBe(false);
    // only the top-level clock is ignored: a nested field called «now» counts
    expect(sameData({ a: { now: 1 } }, { a: { now: 9 } })).toBe(false);
    // the guard's data about the agents is part of the comparison: a new difference is a change
    const ag = (n: number) => ({ now: 1, agents: { state: { openTotal: n, drifts: Array.from({ length: n }, (_, i) => ({ id: i })) } } });
    expect(sameData(ag(1), ag(2))).toBe(false);
    expect(sameData(ag(2), { ...ag(2), now: 99 })).toBe(true);
  });
});

describe("pilot round 2", () => {
  it("a plugin held by the guard is enabled but not running (by status, and by the core's note)", async () => {
    const { isRunning, runningThirdParty } = await import("../src/probe.ts");
    const p = (id: string, status: string, statusDetail: string | null = null) => ({ id, provenance: "local", enabled: true, status, statusDetail, version: "1", source: "path:/x", rootDir: "/x" });
    expect(isRunning({ status: "disabled", statusDetail: null })).toBe(false);
    expect(isRunning({ status: "starting", statusDetail: 'waiting for activation guard "secure-bb"' })).toBe(false);
    expect(isRunning({ status: "running", statusDetail: null })).toBe(true);
    expect(runningThirdParty([p("evil-env", "disabled"), p("held", "starting", "held by secure-bb: review #3"), p("ok", "running"), { ...p("secure-bb", "running") }])).toEqual(["ok"]);
  });
  it("every line of «Пока вас не было» names its plugin, so two plugins' «остановлены» do not read as a contradiction", () => {
    const stop = (pluginId: string, n: number) => ({ pluginId, counts: { auto: 0, window: 0, approved: 0, held: 0, stopped: n, rejected: 0, deleted: 0, alarm: 0 } });
    expect(awayText(stop("evil-env", 2))).toBe("evil-env: 2 остановлены");
    expect(awayText(stop("hello", 1))).toBe("hello: 1 остановлена");
    const hold = (ts: number, pluginId: string): AwayEvent => ({ ts, kind: "hold", pluginId, detail: { stop: true }, from: "guard" });
    const lines = groupAway([hold(T0 + 1, "evil-env"), hold(T0 + 2, "hello")], T0, true, { "evil-env": { yellow: 0, red: 2 }, hello: { yellow: 0, red: 1 } }).map((g) => g.text);
    expect(lines.sort()).toEqual(["evil-env: 2 остановлены", "hello: 1 остановлена"]);
    expect(new Set(lines.map((l) => l.split(":")[0])).size).toBe(lines.length); // one line per plugin
  });
});
