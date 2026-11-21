// UX v1, PR 2: the page's choices as pure functions (status, first problem, card colour, plain words, "while you were away", key names).
import { describe, expect, it } from "vitest";
import {
  AWAY_KEY, MODE_DESCRIPTIONS, MODE_NAMES, TECHNICAL_WORDS, TOUCH_SLOW_HINT, aaguidName, awaySince, awayText, capabilityPhrase, capabilityPhrases, cardColor, classifyAway,
  cleanWhy, deferKey, detailLevel, groupAway, isBlockedEntry, isPasswordManager, pageStatus, parseDeferred, plural, redText, sourceLabel, suggestSources, touchWithHint,
  wizardNeeded, yellowText, GUARD_DOWN_TEXT, SAVED_NARROWING,
} from "../src/ux.ts";
import { MISMATCH_HINT, bypassAllowed, isMismatch, mismatchText, quarantineCount, reasonKind } from "../src/ux.ts";
import type { AwayEvent, StatusInput } from "../src/ux.ts";

const none: StatusInput = { guardDown: false, red: [], yellow: [], alarms: [] };
const ref = (anchor: string, tab: "status" | "more" = "status") => ({ anchor, tab, text: anchor });

describe("status and the first problem", () => {
  it("nothing wrong: «Защищено», no button", () => {
    const s = pageStatus(none);
    expect(s).toMatchObject({ level: "ok", label: "Защищено", count: 0, first: null });
  });
  it("something waits: «Требует внимания (N)» counts every kind", () => {
    const s = pageStatus({ ...none, yellow: [ref("y1"), ref("y2")], alarms: [ref("a1"), ref("a2")] });
    expect(s.level).toBe("attention");
    expect(s.label).toBe("Требует внимания (4)");
    expect(s.count).toBe(4);
  });
  it("order: guard, then red, then yellow, then the watchers' alarms", () => {
    const s = pageStatus({ guardDown: true, red: [ref("r1")], yellow: [ref("y1")], alarms: [ref("a1")] });
    expect(s.problems.map((p) => p.kind)).toEqual(["guard", "red", "yellow", "alarm"]);
    expect(s.first?.kind).toBe("guard");
    expect(pageStatus({ ...none, red: [ref("r1")], yellow: [ref("y1")], alarms: [ref("a1")] }).first?.anchor).toBe("r1");
    expect(pageStatus({ ...none, yellow: [ref("y1")], alarms: [ref("a1")] }).first?.anchor).toBe("y1");
    expect(pageStatus({ ...none, alarms: [ref("a1", "more")] }).first).toMatchObject({ anchor: "a1", tab: "more", kind: "alarm" });
  });
  it("the guard that does not answer is «Защита не работает» whatever else there is", () => {
    const s = pageStatus({ ...none, guardDown: true });
    expect(s).toMatchObject({ level: "down", label: "Защита не работает", count: 1 });
    expect(s.first).toMatchObject({ kind: "guard", anchor: "sbb-guard-alarm", tab: "status" });
    expect(pageStatus({ guardDown: true, red: [ref("r")], yellow: [], alarms: [] }).level).toBe("down");
  });
  it("the first card of a kind leads, in the order they were given", () => {
    expect(pageStatus({ ...none, red: [ref("r2"), ref("r1")] }).first?.anchor).toBe("r2");
  });
});

describe("card colour", () => {
  const f = (severity: string, rule = "x") => ({ rule, severity });
  it("a hard flag in the checks is red; a new right or an unknown source is yellow", () => {
    expect(cardColor({ reason: null, findings: [f("block", "decode-eval")] })).toBe("red");
    expect(cardColor({ reason: null, findings: [f("review"), f("info")] })).toBe("yellow");
    expect(cardColor({ reason: "новое право: network", findings: [] })).toBe("yellow");
    expect(cardColor({ reason: "неизвестный источник", findings: [] })).toBe("yellow");
  });
  it("the core's own words for a block are red too, even before the checks arrive", () => {
    expect(cardColor({ reason: "заблокировано проверками: decode-eval", findings: [] })).toBe("red");
    expect(cardColor({ reason: "жёсткий флаг: decode-eval", findings: [] })).toBe("red");
    expect(isBlockedEntry({ reason: "заблокирован проверками secure-bb", findings: [] })).toBe(true);
  });
  it("only «block» is red: «review» findings never are", () => {
    expect(cardColor({ reason: null, findings: [f("review", "env-secret-network")] })).toBe("yellow");
  });
});

describe("plain words: the main line has no technical words", () => {
  const RULES = ["secret-read-network", "env-dump", "decode-eval", "download-exec", "rc-or-agent-config-write", "contribute-env-dangerous", "install-script", "url-dependency", "url-import", "invisible-chars", "minified", "binary", "native-module", "agent-config", "npmrc", "writable-by-others", "escaping-symlink", "special-file", "sqlite-extension", "some-new-rule"];
  it("every red text (known rule or not) is free of «хеш», «AST», «манифест»", () => {
    for (const r of RULES) {
      const t = redText([r]);
      expect(`${t.title} ${t.line}`, r).not.toMatch(TECHNICAL_WORDS);
      expect(t.title.length).toBeGreaterThan(5);
    }
    expect(redText([])).toMatchObject({ rule: null });
    expect(redText(["nope", "decode-eval"]).rule).toBe("decode-eval");
  });
  it("every right is one plain phrase", () => {
    for (const kind of ["network", "child_process", "env", "fs", "dynamic_code", "ui", "http_routes", "contribute_env", "host_artifact", "builtin_rpc", "server_access", "database", "brand-new"]) {
      expect(capabilityPhrase({ kind, detail: [] }), kind).not.toMatch(TECHNICAL_WORDS);
    }
    expect(capabilityPhrase({ kind: "network", detail: ["host:api.figma.com", "module:node:https"] })).toBe("обращаться по сети только к api.figma.com (других адресов в коде не найдено)");
    expect(capabilityPhrases([{ kind: "env", detail: [] }, { kind: "fs", detail: [] }])).toHaveLength(2);
  });
  it("the yellow card names the plugin, what it can do, and that it does not run meanwhile", () => {
    const t = yellowText({ pluginId: "figma-sync", version: "1.2.0", level: "unknown", sourceLabel: "github.com/acme/figma", reason: "неизвестный источник", caps: [{ kind: "network", detail: ["host:api.figma.com"] }, { kind: "fs", detail: [] }] });
    expect(t.title).toBe("«figma-sync» 1.2.0 ждёт вашего решения");
    expect(t.line).toContain("github.com/acme/figma");
    expect(t.line).toContain("обращаться по сети только к api.figma.com");
    expect(t.line).toContain("Пока вы не решите, он не запускается.");
    expect(`${t.title} ${t.line}`).not.toMatch(TECHNICAL_WORDS);
  });
  it("a new right of a source of the owner says so, and a plugin without rights says that", () => {
    const own = yellowText({ pluginId: "p", version: "2", level: "own", sourceLabel: "github.com/me/p", reason: "новое право: network", caps: [{ kind: "network", detail: [] }] });
    expect(own.line).toContain("вашего источника");
    expect(own.line).toContain("просит новое, чего раньше не просил");
    expect(yellowText({ pluginId: "p", version: "2", level: "unknown", sourceLabel: "x", reason: "неизвестный источник", caps: [] }).line).toContain("Особых прав он не просит");
  });
  it("modes, status texts and hints have no technical words either", () => {
    for (const m of ["simple", "detailed", "strict"] as const) expect(`${MODE_NAMES[m]} ${MODE_DESCRIPTIONS[m]}`).not.toMatch(TECHNICAL_WORDS);
    for (const t of [GUARD_DOWN_TEXT, SAVED_NARROWING, TOUCH_SLOW_HINT, pageStatus(none).label, pageStatus({ ...none, guardDown: true }).label]) expect(t).not.toMatch(TECHNICAL_WORDS);
  });
  it("the guard's reason may be technical, and it is not in the main line", () => {
    const t = yellowText({ pluginId: "p", version: "1", level: "unknown", sourceLabel: "s", reason: "хеш каталога не совпал с хешем из запроса", caps: [] });
    expect(`${t.title} ${t.line}`).not.toMatch(TECHNICAL_WORDS);
  });
  it("the author's why is cleaned: one line, no control or bidi characters, short", () => {
    expect(cleanWhy("  загружаю\u0000 превью\n макетов  ")).toBe("загружаю превью макетов");
    expect(cleanWhy("a‮b​c")).toBe("a b c");
    expect(cleanWhy("x".repeat(500))!.length).toBe(240);
    expect(cleanWhy("")).toBeNull();
    expect(cleanWhy("   ")).toBeNull();
    expect(cleanWhy(42)).toBeNull();
    expect(cleanWhy({ toString: () => "x" })).toBeNull();
  });
  it("where a version came from, in words", () => {
    expect(sourceLabel("git", "git:https://github.com/acme/figma-sync.git@main#sub")).toBe("github.com/acme/figma-sync");
    expect(sourceLabel("git", "git:git@github.com:acme/x")).toBe("github.com/acme/x");
    expect(sourceLabel("path", "path:/Users/me/plugins/p")).toBe("из папки /Users/me/plugins/p");
    expect(sourceLabel("npm", "npm:left-pad")).toBe("npm: left-pad");
  });
});

describe("modes change what is shown", () => {
  it("Simple folds, Detailed opens, Strict opens with hashes and has no bypass", () => {
    expect(detailLevel("simple")).toEqual({ expanded: false, hashes: false, bypass: true });
    expect(detailLevel("detailed")).toEqual({ expanded: true, hashes: false, bypass: true });
    expect(detailLevel("strict")).toEqual({ expanded: true, hashes: true, bypass: false });
  });
  it("without a guard (no mode) the page behaves as Simple", () => {
    expect(detailLevel(null)).toEqual(detailLevel("simple"));
  });
});

describe("«Пока вас не было»", () => {
  const T0 = 1_000_000;
  const g = (kind: string, pluginId: string | null, dt: number, detail: unknown = null, threadId: string | null = null): AwayEvent => ({ ts: T0 + dt, kind, pluginId, threadId, detail, from: "guard" });
  it("«4 версии figma-sync прошли сами, 1 остановлена»", () => {
    const events = [
      g("approved.source", "figma-sync", 1),
      g("approved.source", "figma-sync", 2),
      g("approved.source", "figma-sync", 3),
      g("approved.source", "figma-sync", 4),
      g("hold", "figma-sync", 5, { stop: true }),
    ];
    const groups = groupAway(events, T0, true);
    expect(groups).toHaveLength(1);
    expect(groups[0]!.text).toBe("4 версии figma-sync прошли сами, 1 остановлена");
    expect(groups[0]!.counts).toMatchObject({ auto: 4, stopped: 1 });
  });
  it("«1 остановлена» is said once: not again on a line of its own, whatever threads the records came from and whether the record has a plugin", () => {
    const events = [
      g("approved.source", "figma-sync", 1, {}, "T1"),
      g("approved.source", "figma-sync", 2, {}, "T1"),
      g("hold", "figma-sync", 3, { stop: true }, "T2"),
      g("hold", "figma-sync", 4, { stop: true }, null),
      g("hold", null, 5, { stop: true }, null),
    ];
    for (const held of [{ "figma-sync": { yellow: 0, red: 1 } }, undefined]) {
      const lines = groupAway(events, T0, true, held).map((x) => x.text);
      expect(lines.join("\n").match(/остановлен/g) ?? []).toHaveLength(1);
      expect(lines.some((l) => /^\d+ остановлен/.test(l) && lines.length > 1 && lines.some((o) => o !== l && /остановлен/.test(o)))).toBe(false);
    }
    // the same plugin, one thread: still one line with both parts
    const one = groupAway([g("approved.source", "p", 1, {}, "T1"), g("approved.source", "p", 2, {}, "T1"), g("hold", "p", 3, { stop: true }, "T1")], T0, true, { p: { yellow: 0, red: 1 } });
    expect(one.map((x) => x.text)).toEqual(["2 версии p прошли сами, 1 остановлена"]);
  });
  it("counts agree in number: 1 версия прошла, 5 версий прошли", () => {
    expect(awayText({ pluginId: "p", counts: { auto: 1, window: 0, approved: 0, held: 0, stopped: 0, rejected: 0, deleted: 0, alarm: 0 } })).toBe("1 версия p прошла сама");
    expect(awayText({ pluginId: "p", counts: { auto: 5, window: 0, approved: 0, held: 2, stopped: 0, rejected: 3, deleted: 0, alarm: 0 } })).toBe("5 версий p прошли сами, 2 версии ждут вашего решения, 3 отклонены");
    expect(awayText({ pluginId: "p", counts: { auto: 21, window: 0, approved: 0, held: 0, stopped: 22, rejected: 0, deleted: 0, alarm: 0 } })).toBe("21 версия p прошла сама, 22 остановлены");
    expect(plural(11, "а", "б", "в")).toBe("в");
    expect(plural(12, "а", "б", "в")).toBe("в");
    expect(plural(101, "а", "б", "в")).toBe("а");
  });
  it("events from before the last «Всё в порядке» are not counted; the boundary is exclusive", () => {
    const events = [g("approved.source", "a", -5), g("approved.source", "a", 0), g("approved.source", "a", 1)];
    expect(groupAway(events, T0, true)[0]!.counts.auto).toBe(1);
    expect(groupAway(events, T0 + 100, true)).toEqual([]);
  });
  it("grouped by plugin and by thread", () => {
    const events = [g("approved.source", "a", 1, null, "thr_1"), g("approved.source", "a", 2, null, "thr_2"), g("approved.source", "b", 3, null, "thr_1"), g("approved.source", "a", 4, null, "thr_1")];
    const groups = groupAway(events, T0, true);
    expect(groups).toHaveLength(3);
    const a1 = groups.find((x) => x.pluginId === "a" && x.threadId === "thr_1")!;
    expect(a1.counts.auto).toBe(2);
  });
  it("what needs a person comes first: stopped and alarms, then waiting, then the quiet ones", () => {
    const events = [g("approved.source", "quiet", 10), g("hold", "waits", 5, { note: "неизвестный источник" }), g("hold", "stopped", 1, { stop: true })];
    expect(groupAway(events, T0, true).map((x) => x.pluginId)).toEqual(["stopped", "waits", "quiet"]);
  });
  it("classification of the guard's journal", () => {
    const c = (kind: string, detail?: unknown) => classifyAway(g(kind, "p", 1, detail), true);
    expect(c("approved.source")).toBe("auto");
    expect(c("approved.window")).toBe("window");
    expect(c("approved.touch")).toBe("approved");
    expect(c("hold", { note: "новое право: network" })).toBe("held");
    expect(c("hold", { stop: true })).toBe("stopped");
    expect(c("hold", { note: "жёсткий флаг: decode-eval" })).toBe("stopped");
    expect(c("dismissed")).toBe("deleted");
    expect(c("reject")).toBe("rejected");
    expect(c("agents.critical")).toBe("alarm");
    expect(c("totp.blocked")).toBeNull();
    expect(c("passkey.enrolled")).toBeNull();
  });
  it("with a guard its journal tells the decisions; the plugin's copies are not counted twice, but its alarms are", () => {
    const fromPlugin = (kind: string): AwayEvent => ({ ts: T0 + 1, kind, pluginId: "p", detail: null, from: "plugin" });
    expect(classifyAway(fromPlugin("hold"), true)).toBeNull();
    expect(classifyAway(fromPlugin("approved.touch"), true)).toBeNull();
    expect(classifyAway(fromPlugin("window.taint"), true)).toBe("alarm");
    expect(classifyAway(fromPlugin("journal.alarm"), true)).toBe("alarm");
    // Without a guard the plugin's journal is the one.
    expect(classifyAway(fromPlugin("approved.touch"), false)).toBe("approved");
    expect(classifyAway(fromPlugin("dismissed"), false)).toBe("deleted");
    expect(classifyAway(g("approved.source", "p", 1), false)).toBeNull();
  });
  it("a plugin's blocked hold is «остановлена» without a guard", () => {
    const e: AwayEvent = { ts: T0 + 1, kind: "hold", pluginId: "p", detail: { reason: "заблокировано проверками: decode-eval" }, from: "plugin" };
    expect(classifyAway(e, false)).toBe("stopped");
  });
  it("one record seen twice is one event", () => {
    const e = g("approved.source", "p", 1, { approval: 7 });
    expect(groupAway([e, { ...e }], T0, true)[0]!.counts.auto).toBe(1);
  });
  it("a system alarm without a plugin has its own line", () => {
    const groups = groupAway([{ ts: T0 + 1, kind: "journal.alarm", pluginId: null, detail: null, from: "plugin" }], T0, true);
    expect(groups[0]!.text).toBe("1 тревога системы");
  });
  it("nothing to say, no groups", () => {
    expect(groupAway([], T0, true)).toEqual([]);
    expect(groupAway([g("totp.blocked", null, 1)], T0, true)).toEqual([]);
  });
  it("«since»: the stored moment, else a day back; garbage and the future do not count", () => {
    const now = 10 * 24 * 3600_000;
    expect(awaySince("5000", now)).toBe(5000);
    expect(awaySince(null, now)).toBe(now - 24 * 3600_000);
    expect(awaySince("abc", now)).toBe(now - 24 * 3600_000);
    expect(awaySince(String(now + 1), now)).toBe(now - 24 * 3600_000);
    expect(awaySince("0", now)).toBe(now - 24 * 3600_000);
    expect(AWAY_KEY).toMatch(/away/);
  });
  it("cards put aside: a key per version; garbage in storage is an empty list", () => {
    expect(deferKey("p", "abc", 3)).toBe("p:abc:#3");
    expect(deferKey("p", null, 3)).toBe("p:-:#3");
    // the same code held again later is another entry: an old «отложено» does not carry over
    expect(deferKey("p", "abc", 9)).not.toBe(deferKey("p", "abc", 3));
    expect(parseDeferred('["a","b",1,null]')).toEqual(["a", "b"]);
    expect(parseDeferred("{")).toEqual([]);
    expect(parseDeferred('{"a":1}')).toEqual([]);
    expect(parseDeferred(null)).toEqual([]);
  });
});

describe("where a key is stored (AAGUID)", () => {
  it("names the known stores", () => {
    expect(aaguidName("50726f746f6e5061737350726f746f6e")).toBe("Proton Pass");
    expect(aaguidName("fbfc3007-154e-4ecc-8c0b-6e020557d7bd")).toBe("iCloud-связка");
    expect(aaguidName("ADCE0002-35BC-C60A-648B-0B25F1F05503")).toBe("Chrome (Touch ID)");
    expect(aaguidName("bada5566a7aa401fbd9645619a55120d")).toBe("1Password");
    expect(aaguidName("6028b017-b1d4-4c02-b4b3-afcdafc96bb2")).toBe("Windows Hello");
  });
  it("«ProtonPassProton» as the owner's stand reported it", () => {
    expect(aaguidName(Buffer.from("ProtonPassProton").toString("hex"))).toBe("Proton Pass");
  });
  it("an unknown, empty or zero AAGUID is «другое»", () => {
    expect(aaguidName("12345678123456781234567812345678")).toBe("другое");
    expect(aaguidName("00000000000000000000000000000000")).toBe("другое");
    expect(aaguidName("")).toBe("другое");
    expect(aaguidName(undefined)).toBe("другое");
    expect(aaguidName(null)).toBe("другое");
    expect(aaguidName("not hex at all")).toBe("другое");
  });
  it("password managers are the ones whose extension may take the request", () => {
    expect(isPasswordManager("Proton Pass")).toBe(true);
    expect(isPasswordManager("1Password")).toBe(true);
    expect(isPasswordManager("iCloud-связка")).toBe(false);
    expect(isPasswordManager("другое")).toBe(false);
  });
});

describe("touch hints", () => {
  it("the hint about the password manager appears only after the wait", () => {
    expect(touchWithHint("Одобрить p", false)).toBe("Подтвердите касанием. Сторож: «Одобрить p»");
    expect(touchWithHint("Одобрить p", true)).toContain("менеджера паролей");
    expect(touchWithHint("Одобрить p", true)).toContain("1Password");
  });
  it("saving a narrowing says that no touch was needed", () => {
    expect(SAVED_NARROWING).toBe("Сохранено: это сужение, касание не требуется.");
  });
});

describe("first run", () => {
  it("the wizard comes for a guard that knows trust, with no sources and not yet closed", () => {
    expect(wizardNeeded({ hasTrust: true, mySources: 0, done: false })).toBe(true);
    expect(wizardNeeded({ hasTrust: true, mySources: 1, done: false })).toBe(false);
    expect(wizardNeeded({ hasTrust: true, mySources: 0, done: true })).toBe(false);
    expect(wizardNeeded({ hasTrust: false, mySources: 0, done: false })).toBe(false);
  });
  it("suggested sources come from the installed plugins, once each, from what the core said", () => {
    const id = (kind: string, source: string) => (kind === "git" ? `github:${source.slice(4)}` : kind === "path" ? source : null);
    expect(suggestSources([{ source: "git:a/b" }, { source: "git:a/b" }, { source: "path:/x" }, { source: "npm:q" }], id)).toEqual(["github:a/b", "path:/x"]);
    expect(suggestSources([], id)).toEqual([]);
  });
});

describe("review fixes (PR 2, review)", () => {
  const MISMATCH = "хеш каталога, посчитанный сторожем, не совпал с хешем из запроса";
  it("counts: the status and the tab count what the person sees: cards and alarms, nothing else", () => {
    const s = pageStatus({ ...none, red: [ref("r")], yellow: [ref("y1"), ref("y2")], alarms: [ref("a")] });
    expect(s.count).toBe(4);
    expect(s.label).toContain("(");
    expect(pageStatus({ ...none, yellow: [ref("y1"), ref("y2")] }).label).toBe("Требует внимания (2)");
    expect(quarantineCount(2, 1)).toBe(3);
    expect(quarantineCount(0, 0)).toBe(0);
  });
  it("away: what waits is the current list, once per plugin, not once per journal record", () => {
    const T0 = 1_000_000;
    const hold = (dt: number, thread: string): AwayEvent => ({ ts: T0 + dt, kind: "hold", pluginId: "p", threadId: thread, detail: { note: "неизвестный источник" }, from: "guard" });
    const events = [hold(1, "a"), hold(2, "a"), hold(3, "b"), { ts: T0 + 4, kind: "approved.source", pluginId: "p", threadId: "a", detail: {}, from: "guard" } as AwayEvent];
    const groups = groupAway(events, T0, true, { p: { yellow: 3, red: 0 } });
    const lines = groups.map((g) => g.text).join("\n");
    expect(lines.match(/ждут вашего решения/g)).toHaveLength(1);
    expect(lines).toContain("3 версии ждут вашего решения");
    // no hold in the period: nothing is said about waiting, even if something waits from before
    expect(groupAway([{ ts: T0 + 4, kind: "approved.source", pluginId: "p", detail: {}, from: "guard" }], T0, true, { p: { yellow: 3, red: 0 } })[0]!.text).toBe("1 версия p прошла сама");
    // stopped follows the red cards of now
    expect(groupAway([hold(1, "a")], T0, true, { p: { yellow: 0, red: 2 } })[0]!.text).toBe("p: 2 остановлены");
    expect(groupAway([hold(1, "a")], T0, true, { p: { yellow: 0, red: 0 } })).toEqual([]);
  });
  it("away: endings follow the number", () => {
    const c = (auto: number) => awayText({ pluginId: "p", counts: { auto, window: 0, approved: 0, held: 0, stopped: 0, rejected: 0, deleted: 0, alarm: 0 } });
    expect(c(1)).toBe("1 версия p прошла сама");
    expect(c(2)).toBe("2 версии p прошли сами");
    expect(c(5)).toBe("5 версий p прошли сами");
    expect(c(11)).toBe("11 версий p прошли сами");
    expect(c(21)).toBe("21 версия p прошла сама");
    expect(awayText({ pluginId: "p", counts: { auto: 0, window: 1, approved: 0, held: 1, stopped: 0, rejected: 0, deleted: 0, alarm: 0 } })).toBe("1 версия p прошла в окне доверия, 1 версия ждёт вашего решения");
  });
  it("a hash mismatch is red with its own words, not the default yellow", () => {
    expect(isMismatch(MISMATCH)).toBe(true);
    expect(isMismatch("хеш каталога не совпал с хешем из запроса")).toBe(true);
    expect(cardColor({ reason: MISMATCH, findings: [] })).toBe("red");
    expect(reasonKind(MISMATCH)).toBe("mismatch");
    const t = mismatchText("p", "1.0.0");
    expect(t.line).toContain("Так бывает при подмене файлов. Не разрешайте, если не знаете причину.");
    expect(`${t.title} ${t.line}`).not.toMatch(TECHNICAL_WORDS);
    expect(t.line).not.toContain("просит");
  });
  it("yellow words follow the guard's reason and never contradict themselves", () => {
    const y = (reason: string | null, caps: Array<{ kind: string; detail: string[] }> = []) => yellowText({ pluginId: "p", version: "1", level: "own", sourceLabel: "github.com/me/p", reason, caps }).line;
    expect(reasonKind("новое право: network")).toBe("new-right");
    expect(reasonKind("неизвестный источник")).toBe("unknown-source");
    expect(reasonKind("режим «Строгий»: каждая версия ждёт вас")).toBe("strict");
    expect(reasonKind("нет одобренной версии этого плагина из этого источника")).toBe("first-version");
    expect(reasonKind(null)).toBe("other");
    expect(y("режим «Строгий»: каждая версия ждёт вас")).toContain("Строгий");
    expect(y("нет одобренной версии этого плагина из этого источника")).toContain("ещё не разрешали");
    expect(y("новое право: network", [{ kind: "network", detail: ["host:telemetry.example"] }])).toContain("обращаться по сети только к telemetry.example");
    // «просит новое» and «особых прав не просит» never in one text
    for (const r of ["новое право: network", "неизвестный источник", "режим «Строгий»", "нет одобренной версии", null, "странное"]) {
      for (const caps of [[], [{ kind: "fs", detail: [] }]]) {
        const l = y(r, caps);
        expect(l.includes("просит новое") && l.includes("Особых прав"), `${r}`).toBe(false);
      }
    }
  });
  it("the text speaks of the plugin, one gender in a paragraph", () => {
    for (const r of ["новое право: network", "неизвестный источник", "режим «Строгий»", null]) {
      const l = yellowText({ pluginId: "p", version: "1", level: "unknown", sourceLabel: "x", reason: r, caps: [{ kind: "fs", detail: [] }] }).line;
      expect(l, String(r)).not.toMatch(/версия|она|просила/);
    }
    for (const rule of ["decode-eval", "env-dump"]) expect(redText([rule]).line).not.toMatch(/\bона\b|версия/);
    expect(mismatchText("p", "1").line).not.toMatch(/\bона\b/);
  });
  it("a red card makes the whole status red and says how many are stopped", () => {
    const s = pageStatus({ ...none, red: [ref("r1"), ref("r2")], yellow: [ref("y")] });
    expect(s).toMatchObject({ level: "stopped", label: "Остановлено (2)", count: 3 });
    expect(s.first?.anchor).toBe("r1");
    expect(pageStatus({ ...none, yellow: [ref("y")] }).level).toBe("attention");
    expect(pageStatus({ ...none, alarms: [ref("a")] }).level).toBe("attention");
    expect(pageStatus({ guardDown: true, red: [ref("r")], yellow: [], alarms: [] }).level).toBe("down");
  });
});

describe("no bypass on a hash mismatch", () => {
  const MIS = "хеш каталога, посчитанный сторожем, не совпал с хешем из запроса";
  it("in no mode; other red cards keep it except in Strict", () => {
    for (const m of ["simple", "detailed", "strict", null] as const) expect(bypassAllowed(m, MIS), String(m)).toBe(false);
    expect(bypassAllowed("simple", "заблокировано проверками: decode-eval")).toBe(true);
    expect(bypassAllowed("detailed", null)).toBe(true);
    expect(bypassAllowed("strict", "заблокировано проверками: decode-eval")).toBe(false);
  });
  it("the card says what to do instead", () => {
    expect(MISMATCH_HINT).toBe("Переустановите плагин из его источника. Если код снова не совпадёт, сообщите об этом в разделе журнала.");
    expect(mismatchText("p", "1").line).toContain(MISMATCH_HINT);
    expect(MISMATCH_HINT).not.toMatch(TECHNICAL_WORDS);
  });
});
