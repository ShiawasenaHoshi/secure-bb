// UX v1, PR 2: the page's choices as pure functions (status, first problem, card colour, plain words, "while you were away", key names).
import { describe, expect, it } from "vitest";
import {
  AWAY_KEY, MODE_DESCRIPTIONS, MODE_NAMES, TECHNICAL_WORDS, TOUCH_SLOW_HINT, aaguidName, awaySince, awayText, capabilityPhrase, capabilityPhrases, cardColor, classifyAway,
  cleanWhy, deferKey, detailLevel, groupAway, isBlockedEntry, isPasswordManager, pageStatus, parseDeferred, plural, redText, sourceLabel, suggestSources, touchWithHint,
  wizardNeeded, yellowText, GUARD_DOWN_TEXT, SAVED_NARROWING,
} from "../src/ux.ts";
import type { AwayEvent, StatusInput } from "../src/ux.ts";

const none: StatusInput = { guardDown: false, red: [], yellow: [], alarms: [] };
const ref = (anchor: string, tab: "status" | "more" = "status") => ({ anchor, tab, text: anchor });

describe("status and the first problem", () => {
  it("nothing wrong: «Защищено», no button", () => {
    const s = pageStatus(none);
    expect(s).toMatchObject({ level: "ok", label: "Защищено", count: 0, first: null });
  });
  it("something waits: «Требует внимания (N)» counts every kind", () => {
    const s = pageStatus({ ...none, red: [ref("r1")], yellow: [ref("y1"), ref("y2")], alarms: [ref("a1")] });
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
    expect(capabilityPhrase({ kind: "network", detail: ["host:api.figma.com", "module:node:https"] })).toBe("ходить в сеть (api.figma.com)");
    expect(capabilityPhrases([{ kind: "env", detail: [] }, { kind: "fs", detail: [] }])).toHaveLength(2);
  });
  it("the yellow card names the plugin, what it can do, and that it does not run meanwhile", () => {
    const t = yellowText({ pluginId: "figma-sync", version: "1.2.0", level: "unknown", sourceLabel: "github.com/acme/figma", reason: "неизвестный источник", caps: [{ kind: "network", detail: ["host:api.figma.com"] }, { kind: "fs", detail: [] }] });
    expect(t.title).toBe("«figma-sync» ждёт вашего решения");
    expect(t.line).toContain("github.com/acme/figma");
    expect(t.line).toContain("ходить в сеть (api.figma.com)");
    expect(t.line).toContain("Пока вы не решите, он не запускается.");
    expect(`${t.title} ${t.line}`).not.toMatch(TECHNICAL_WORDS);
  });
  it("a new right of a source of the owner says so, and a plugin without rights says that", () => {
    const own = yellowText({ pluginId: "p", version: "2", level: "own", sourceLabel: "github.com/me/p", reason: "новое право: network", caps: [{ kind: "network", detail: [] }] });
    expect(own.line).toContain("вашего источника");
    expect(own.line).toContain("просит то, чего раньше не просила");
    expect(yellowText({ pluginId: "p", version: "2", level: "known", sourceLabel: "x", reason: null, caps: [] }).line).toContain("Особых прав он не просит");
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
    expect(sourceLabel("path", "path:/Users/me/plugins/p")).toBe("папки /Users/me/plugins/p");
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
  it("counts agree in number: 1 версия прошла, 5 версий прошли", () => {
    expect(awayText({ pluginId: "p", counts: { auto: 1, window: 0, approved: 0, held: 0, stopped: 0, rejected: 0, alarm: 0 } })).toBe("1 версия p прошла сами");
    expect(awayText({ pluginId: "p", counts: { auto: 5, window: 0, approved: 0, held: 2, stopped: 0, rejected: 3, alarm: 0 } })).toBe("5 версий p прошли сами, 2 версии ждут вашего решения, 3 отклонены");
    expect(awayText({ pluginId: "p", counts: { auto: 21, window: 0, approved: 0, held: 0, stopped: 22, rejected: 0, alarm: 0 } })).toBe("21 версия p прошла сами, 22 остановлены");
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
    expect(c("dismissed")).toBe("rejected");
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
    expect(classifyAway(fromPlugin("dismissed"), false)).toBe("rejected");
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
    expect(deferKey("p", "abc", 3)).toBe("p:abc");
    expect(deferKey("p", null, 3)).toBe("p:#3");
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
