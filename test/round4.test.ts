// Round 4 of the pilot (persona «Марина»): what a card says first, rights worth showing, a page that holds still, the wizard's words.
import { describe, expect, it } from "vitest";
import {
  AWAY_HIDE_LABEL, MIN_STUB_HEIGHT, agentConfigNote, approveVerb, awaySince, awayText, capabilityPhrase, capsWithPaths, classifyAway, enabledWhat, friendlySource, groupAway, layoutItems, makeStub, meaningfulCaps,
  redText, riskHeadline, scopeText, secondFactorText, stableOrder, WIZARD_SOURCES_TEXT, type CapLike,
} from "../src/ux.js";

const cap = (kind: string, ...detail: string[]): CapLike => ({ kind, detail });

describe("3. the right «dynamic_code» is shown only for eval / new Function / vm with a built argument", () => {
  it("drops noise: literal Function, .constructor, property access, import(expression), process.getBuiltinModule", () => {
    const noisy = [cap("dynamic_code", "new Function(literal)", ".constructor", "dynamic property access", "import(expression)", "process.getBuiltinModule", "Function(literal)")];
    expect(meaningfulCaps(noisy)).toEqual([]);
  });
  it("keeps eval, new Function and vm without a literal argument, and only those details", () => {
    const got = meaningfulCaps([cap("dynamic_code", "eval", "new Function", ".constructor", "new Function(literal)", "vm.runInContext", "vm")]);
    expect(got).toEqual([cap("dynamic_code", "eval", "new Function", "vm.runInContext", "vm")]);
  });
  it("other rights are untouched; capsWithPaths applies the filter (the card's own list)", () => {
    const r = { capabilities: [cap("ui", "x"), cap("dynamic_code", "dynamic property access"), cap("fs", "node:fs")], fsPaths: ["a.json"] };
    expect(capsWithPaths(r)).toEqual([cap("ui", "x"), { kind: "fs", detail: ["node:fs"], paths: ["a.json"] }]);
  });
});

describe("4. «database» is the plugin's own storage", () => {
  it("is told as keeping its own settings and data in bb", () => {
    expect(capabilityPhrase(cap("database", "bb.storage.database"))).toBe("хранить свои настройки и данные в bb");
  });
});

describe("10. the agent-config words", () => {
  it("do not say what agents are allowed", () => {
    const t = redText(["agent-config"]);
    expect(`${t.title} ${t.line}`).not.toMatch(/разрешают|не спрашивают/);
    expect(t.line).toMatch(/внутри самого плагина/);
  });
  it("a plugin's own agent settings are a note on a yellow card, nothing else", () => {
    expect(agentConfigNote([{ rule: "agent-config" }])).toMatch(/не применяет/);
    expect(agentConfigNote([{ rule: "minified" }])).toBeNull();
  });
});

describe("6, 7. the first line says the essence of the risk", () => {
  it("all of the environment: passwords and tokens", () => {
    expect(riskHeadline([cap("env", "*")])).toEqual({ level: "danger", text: "Может читать ваши пароли и токены" });
    expect(riskHeadline([cap("env")]).text).toBe("Может читать ваши пароли и токены");
    expect(riskHeadline([cap("env", "env:GITHUB_TOKEN")]).level).toBe("danger");
  });
  it("files without named paths: documents", () => {
    expect(riskHeadline([cap("fs", "node:fs")])).toEqual({ level: "danger", text: "Может читать и менять ваши документы" });
  });
  it("files with named paths are a caution with the paths", () => {
    const r = riskHeadline([{ kind: "fs", detail: ["node:fs"], paths: ["a.json", "b.json", "c.json"] }]);
    expect(r.level).toBe("caution");
    expect(r.text).toBe("Может читать и менять файлы: a.json, b.json, …");
  });
  it("programs, network with and without hosts", () => {
    expect(riskHeadline([cap("child_process", "node:child_process")]).text).toBe("Может запускать программы на вашем компьютере");
    expect(riskHeadline([cap("network", "host:json-schema.org")]).text).toBe("Может обращаться по сети к json-schema.org");
    expect(riskHeadline([cap("network", "fetch")]).text).toBe("Может выходить в интернет на любые адреса");
  });
  it("the worst right leads: passwords before network", () => {
    expect(riskHeadline([cap("network", "host:x.io"), cap("env", "*"), cap("ui", "x")]).level).toBe("danger");
  });
  it("only look and its own data: safe, one button «Включить»", () => {
    const r = riskHeadline([cap("ui", "@get-bb/plugin-sdk/app"), cap("database", "bb.storage.database")]);
    expect(r).toEqual({ level: "safe", text: "Безопасно: только оформление — ничего не читает" });
    expect(approveVerb(r)).toBe("Включить");
    expect(approveVerb({ level: "caution", text: "" })).toBe("Разрешить");
    expect(riskHeadline([]).level).toBe("safe");
  });
  it("noise rights do not spoil «безопасно» (a theme with Function('return this'))", () => {
    const r = riskHeadline(meaningfulCaps([cap("ui", "x"), cap("dynamic_code", "new Function(literal)", "dynamic property access")]));
    expect(r.level).toBe("safe");
  });
  it("a real eval is not safe; an unexplained review finding is not safe; agent-config alone is", () => {
    expect(riskHeadline(meaningfulCaps([cap("ui", "x"), cap("dynamic_code", "eval")])).level).toBe("caution");
    expect(riskHeadline([cap("ui", "x")], ["dynamic-import"]).level).toBe("caution");
    expect(riskHeadline([cap("ui", "x")], ["agent-config"]).level).toBe("safe");
  });
  it("the sentence about scope moved out of the first lines", () => {
    expect(scopeText("0.1.0")).toBe("Версия 0.1.0: всё, что вы нажмёте на этой карточке, относится только к ней.");
  });
});

describe("8. after «Разрешить»", () => {
  it("the stub says what was switched on", () => {
    expect(makeStub("chime", enabledWhat("chime", "0.1.0"), 120).text).toBe("Готово: включён chime 0.1.0");
  });
  it("«Пока вас не было» counts the approval with trust as well", () => {
    expect(classifyAway({ ts: 1, kind: "approved.trust", pluginId: "chime", from: "guard" }, true)).toBe("approved");
    const g = groupAway([{ ts: 5, kind: "approved.touch", pluginId: "chime", from: "guard" }, { ts: 6, kind: "approved.trust", pluginId: "bell", from: "guard" }], 0, true);
    expect(g.map((x) => x.text).sort()).toEqual(["1 версия bell одобрена", "1 версия chime одобрена"]);
    expect(awayText({ pluginId: "x", counts: { auto: 0, window: 0, approved: 2, held: 0, stopped: 0, rejected: 0, deleted: 0, alarm: 0 } })).toBe("2 версии x одобрены");
  });
});

describe("5. the page holds still", () => {
  it("a stub has the height of the card it replaces (not less than the minimum)", () => {
    expect(makeStub("a", "включён a 1", 240).height).toBe(240);
    expect(makeStub("a", "включён a 1", 10).height).toBe(MIN_STUB_HEIGHT);
    expect(makeStub("a", "включён a 1", Number.NaN).height).toBe(MIN_STUB_HEIGHT);
  });
  it("the first list is taken as it comes and nothing is marked new", () => {
    expect(stableOrder(null, ["b", "a", "c"])).toEqual({ order: ["b", "a", "c"], fresh: [] });
  });
  it("what was there keeps its place whatever the new order of the server; new goes to the end, marked", () => {
    const first = stableOrder(null, ["b", "a", "c"]);
    const next = stableOrder(first.order, ["c", "n1", "a", "b", "n2"]);
    expect(next.order).toEqual(["b", "a", "c", "n1", "n2"]);
    expect(next.fresh).toEqual(["n1", "n2"]);
    // a later look: the order stays, «new» is told only for what has not been placed yet
    expect(stableOrder(next.order, ["n2", "b", "n1", "c", "a"]).order).toEqual(["b", "a", "c", "n1", "n2"]);
  });
  it("a resolved card leaves the list, unless a stub stands in its place", () => {
    const order = ["a", "b", "c"];
    expect(stableOrder(order, ["a", "c"]).order).toEqual(["a", "c"]);
    expect(stableOrder(order, ["a", "c"], ["b"]).order).toEqual(["a", "b", "c"]);
  });
  it("layoutItems: a card where there is one, the stub where it was resolved, nothing for the rest", () => {
    const stub = makeStub("b", "включён b 1", 100);
    expect(layoutItems(["a", "b", "c", "d"], new Set(["a", "c"]), [stub])).toEqual([{ key: "a" }, { key: "b", stub }, { key: "c" }]);
    // the plugin came back (a new version): the card wins over the stub
    expect(layoutItems(["b"], new Set(["b"]), [stub])).toEqual([{ key: "b" }]);
  });
  it("«С …» of «Пока вас не было» does not move while the page is open", () => {
    const start = Date.UTC(2026, 10, 20, 23, 31, 0);
    expect(awaySince(null, start)).toBe(awaySince(null, start));
    expect(awaySince(null, start)).toBe(start - 24 * 3600 * 1000);
    // after «Понятно, скрыть» the mark is newer than the start: it is taken as it is
    const mark = start + 5000;
    expect(awaySince(String(mark), Math.max(start, mark))).toBe(mark);
  });
});

describe("9. the wizard", () => {
  it("a source in words", () => {
    expect(friendlySource("github:charpeni/bb-plugins")).toBe("charpeni/bb-plugins (на GitHub)");
    expect(friendlySource("path:/home/me/plugins")).toBe("папка /home/me/plugins");
    expect(WIZARD_SOURCES_TEXT).toMatch(/ничего отмечать не нужно/);
    expect(WIZARD_SOURCES_TEXT).not.toMatch(/github:/);
  });
  it("the second factor is never «ключей: 0»", () => {
    expect(secondFactorText({ codes: true, keys: 0 })).toBe("Второй фактор настроен: коды из приложения на телефоне.");
    expect(secondFactorText({ codes: true, keys: 2 })).toMatch(/и ключ/);
    expect(secondFactorText({ codes: false, keys: 1 })).toMatch(/ключ/);
    expect(secondFactorText({ codes: false, keys: 0 })).toBe("Второй фактор ещё не настроен.");
    for (const i of [{ codes: true, keys: 0 }, { codes: false, keys: 3 }]) expect(secondFactorText(i)).not.toMatch(/ключей:/);
  });
  it("the hide button does not ask whether «всё в порядке»", () => {
    expect(AWAY_HIDE_LABEL).toBe("Понятно, скрыть");
  });
});
