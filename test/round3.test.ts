import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { foldState, isFoldOpen, openFold, toggleFold } from "../src/fold.js";
import {
  alarmCount,
  approvalWhy,
  approvedByText,
  approvedNote,
  awayAlarms,
  canRestore,
  capabilityPhrase,
  capsWithPaths,
  cardFoldId,
  clockText,
  firstButtonAfter,
  humanError,
  pageStatus,
  redWhere,
  rejectedAtOf,
  rejectedByText,
  sessionClosedText,
  sessionEndReason,
  slideIdle,
  trustButton,
  uniqueSentences,
  windowAvailability,
  yellowText,
} from "../src/ux.js";
import { runChecks } from "../src/checks/index.js";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
// @ts-expect-error jsdom ships no types in this tree
import { JSDOM } from "jsdom";

const app = readFileSync(new URL("../app.tsx", import.meta.url), "utf8");

describe("1. every fold is a Fold with a stable id", () => {
  it("app.tsx has no bare <details> except the one inside Fold itself", () => {
    const code = app.split("\n").map((l) => (/^\s*(\/\*|\*|\/\/)/.test(l) ? "" : l)).join("\n");
    const bare = [...code.matchAll(/<details\b/g)];
    expect(bare.length).toBe(1);
    expect(code.slice(0, bare[0]!.index)).toMatch(/function Fold\(/);
  });

  it("no component is declared inside another component (it would be unmounted at every draw)", () => {
    // A component starts a line with a capital: `function Name(` / `const Name = (` at the top level (no indent). Indented ones are inner.
    const inner = app.split("\n").filter((l) => /^\s+(function [A-Z]\w*\s*\(|const [A-Z]\w*\s*(:[^=]+)?=\s*(\([^)]*\)|\w+)\s*=>)/.test(l));
    expect(inner).toEqual([]);
  });

  it("fold ids are never made from an index or a queue number alone", () => {
    const ids = [...app.matchAll(/<Fold id=\{?([^ >]+?)\}? /g)].map((m) => m[1]!);
    expect(ids.length).toBeGreaterThan(20);
    for (const id of ids) expect(id, id).not.toMatch(/\$\{(i|idx|index)\}/);
  });

  it("a fold stays as the person left it when the page is drawn again with new data", () => {
    foldState.open = {};
    // A card of the same version whose queue entry got a new number: the same fold.
    const before = { pluginId: "p", version: "1.0.0", contentHash: "h1", id: 7 };
    const after = { pluginId: "p", version: "1.0.0", contentHash: "h1", id: 12 };
    expect(isFoldOpen(cardFoldId(before, "tech"))).toBe(false);
    toggleFold(cardFoldId(before, "tech"));
    expect(isFoldOpen(cardFoldId(after, "tech"))).toBe(true);
    // a click on an open fold closes it, also after a redraw
    toggleFold(cardFoldId(after, "tech"));
    expect(isFoldOpen(cardFoldId(before, "tech"))).toBe(false);
    // `defaultOpen` counts only until the first touch
    expect(isFoldOpen("x", true)).toBe(true);
    toggleFold("x", true);
    expect(isFoldOpen("x", true)).toBe(false);
    openFold("deferred", true);
    expect(isFoldOpen("deferred")).toBe(true);
  });

  it("in a real DOM: the open attribute follows the state, and a redraw with other data keeps it", () => {
    const dom = new JSDOM("<details id=a><summary>s</summary>body</details>");
    const el = dom.window.document.getElementById("a") as HTMLDetailsElement;
    foldState.open = {};
    const draw = (id: string) => {
      el.open = isFoldOpen(id);
    };
    draw("f1");
    expect(el.open).toBe(false);
    toggleFold("f1");
    draw("f1");
    expect(el.open).toBe(true);
    draw("f1"); // a new overview arrives: drawn again with the same id
    expect(el.open).toBe(true);
  });
});

describe("2. «Разрешено» and dead buttons", () => {
  it("the line after «Разрешить» is the same kind as «Удалён: …»", () => {
    expect(approvedNote("sbb-test-hello", "0.0.6")).toBe("Разрешено: плагин sbb-test-hello 0.0.6.");
  });
  it("a decision locks the card's buttons until it goes (useCodeAction keeps `locked`)", () => {
    expect(app).toMatch(/setLocked\(true\)/);
    expect(app).toMatch(/busy: busy \|\| locked/);
  });
});

describe("3. the key fact is in the main text", () => {
  it("red: where the data goes", () => {
    expect(redWhere([{ kind: "network", detail: ["host:pdf-cdn.example"] }])).toBe("Данные уходят на: pdf-cdn.example.");
    expect(redWhere([{ kind: "network", detail: ["https"] }])).toContain("из кода не видно");
    expect(redWhere([{ kind: "env", detail: [] }])).toBeNull();
  });
  it("file rights: the paths when the code names them, else «любые файлы… ваши документы»", () => {
    expect(capabilityPhrase({ kind: "fs", detail: ["fs"] })).toContain("любые файлы, к которым у bb есть доступ — в том числе ваши документы");
    const p = capabilityPhrase({ kind: "fs", detail: ["fs"], paths: ["/Users/me/Clients"] });
    expect(p).toContain("/Users/me/Clients");
    expect(p).not.toContain("любые файлы");
    const caps = capsWithPaths({ capabilities: [{ kind: "fs", detail: ["fs"] }, { kind: "network", detail: [] }], fsPaths: ["/a/b"] });
    expect(caps[0]!.paths).toEqual(["/a/b"]);
    expect(caps[1]!.paths).toBeUndefined();
    const y = yellowText({ pluginId: "h", version: "1", level: "own", sourceLabel: "из папки x", reason: "новое право: fs", caps: [{ kind: "fs", detail: ["fs"] }] });
    expect(y.line).toContain("в том числе ваши документы");
  });
  it("the checks read literal paths handed to file calls, and only show them (no new right)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "sbb-fs-"));
    mkdirSync(join(dir, "src"), { recursive: true });
    writeFileSync(join(dir, "package.json"), JSON.stringify({ name: "p", version: "1.0.0" }));
    writeFileSync(join(dir, "src", "a.ts"), `import { readFileSync } from "node:fs";\nexport const x = readFileSync("/Users/me/Clients/list.txt", "utf8");\nexport const y = "/api/route";\n`);
    const r = await runChecks(dir);
    expect(r.fsPaths).toEqual(["/Users/me/Clients/list.txt"]);
    expect(r.capabilities.find((c) => c.kind === "fs")!.detail).toEqual(["fs"]);
  });
});

describe("4. no jargon in the main text", () => {
  const MAIN = /эталон|сторож|тред|окн\w* довер|загрязн/i;
  it("cards, status and notes say it in plain words", () => {
    const y = yellowText({ pluginId: "h", version: "1", level: "unknown", sourceLabel: "x", reason: "нет одобренной версии", caps: [] });
    expect(`${y.title} ${y.line}`).not.toMatch(MAIN);
    expect(windowAvailability({ threadId: null, queueId: 3, sourceKind: "path", level: "own" }).note ?? "").not.toMatch(MAIN);
    expect(windowAvailability({ threadId: null, queueId: 3, sourceKind: "git", level: "own" }).note ?? "").not.toMatch(MAIN);
  });
  it("the page's visible strings of the status tab do not use the old words", () => {
    // The sections that live on the «Подробно» tab keep their technical words; these status-tab pieces must not.
    for (const piece of ["Защита следит за настройками", "Первые одобренные настройки", "«под подозрением»", "Временное доверие: плагин"]) expect(app).toContain(piece);
    for (const gone of ["сверяет их с эталоном", "помечает тред загрязнённым", "помечен загрязнённым", "Сторож решений не отвечает</p>", "первый эталон"]) expect(app).not.toContain(gone);
  });
});

describe("5. the same sentence once; no dead button", () => {
  it("«Ваш источник уже в доверенных…» comes once", () => {
    const w = windowAvailability({ threadId: null, queueId: 4, sourceKind: "path", level: "own" });
    const t = trustButton({ entry: "path:/x", level: "own", queueId: 4 });
    const text = uniqueSentences([w.note, t.note]).join(" ");
    expect(text.match(/уже в доверенных/g)).toHaveLength(1);
  });
  it("a button that would add nothing is not shown", () => {
    expect(trustButton({ entry: "path:/x", level: "own", queueId: 4 }).enabled).toBe(false);
    expect(app).toMatch(/\{trust\.enabled \? <button/);
  });
});

describe("6. loading says «Загрузка…»", () => {
  it("no grey skeleton while the overview is not there", () => {
    expect(app).toMatch(/data-secure-bb-loading>[\s\S]*Загрузка…/);
    expect(app).not.toMatch(/animate-pulse/);
  });
});

describe("7. the session", () => {
  it("says why it closed", () => {
    expect(sessionClosedText("locked")).toContain("Сессия закрыта: вы нажали «Заблокировать»");
    expect(sessionClosedText("idle")).toContain("прошло 15 минут без действий");
    expect(sessionClosedText("ceiling")).toContain("прошёл час");
    expect(sessionClosedText("server")).toMatch(/^Сессия закрыта: /);
    expect(sessionEndReason({ idleUntil: 10, hardUntil: 100 }, 20)).toBe("idle");
    expect(sessionEndReason({ idleUntil: 10, hardUntil: 100 }, 100)).toBe("ceiling");
  });
  it("a use slides the end ahead but never takes time away (an hour session keeps its hour)", () => {
    expect(slideIdle({ idleUntil: 5_000_000 }, 1_000_000, 900_000, 5_000)).toBe(5_000_000);
    expect(slideIdle({ idleUntil: 1_100_000 }, 1_000_000, 900_000, 5_000)).toBe(1_895_000);
  });
  it("Enter in a code field presses the first enabled button after it", () => {
    const dom = new JSDOM(`<div id=g><div id=row><input id=code><button id=off disabled>no</button><button id=ok>yes</button></div><button id=other>x</button></div>`);
    const d = dom.window.document;
    expect(firstButtonAfter(d.getElementById("code")!)?.id).toBe("ok");
    // nothing enabled after it in its row: the next level up is looked at
    d.getElementById("ok")!.setAttribute("disabled", "");
    expect(firstButtonAfter(d.getElementById("code")!)?.id).toBe("other");
    d.getElementById("other")!.setAttribute("disabled", "");
    expect(firstButtonAfter(d.getElementById("code")!)).toBeNull();
    expect(app).toMatch(/e\.key !== "Enter"/);
  });
  it("«Открыть на 1 час» exists and reaches the server as `hour`", () => {
    expect(app).toContain("Открыть на 1 час");
    expect(readFileSync(new URL("../src/contract.ts", import.meta.url), "utf8")).toMatch(/"session\.open": \{ input: s\.object\(\{ \.\.\.factor, hour: s\.optional\(s\.boolean\(\)\) \}\)/);
  });
});

describe("8. who, when and how", () => {
  const now = new Date(2026, 10, 21, 22, 0, 0).getTime();
  const at = (h: number, m: number, day = 21) => new Date(2026, 10, day, h, m, 0).getTime();
  it("a touch: «вы, касанием, 21:26»", () => {
    expect(approvedByText({ via: "touch", approvedAt: at(21, 26) }, now)).toBe("вы, касанием, 21:26");
    expect(approvedByText({ via: "touch", why: "касанием: новое право: fs", approvedAt: at(21, 26) }, now)).toMatch(/^вы, касанием: новое право — .*, 21:26$/);
  });
  it("by itself: «прошла сама: свой источник, 21:20»", () => {
    expect(approvedByText({ via: "source", why: "прошла сама: свой источник", approvedAt: at(21, 20) }, now)).toBe("прошла сама: свой источник, 21:20");
    expect(approvalWhy({ via: "window" })).toContain("временного доверия");
  });
  it("another day carries the date", () => {
    expect(clockText(at(21, 26, 20), now)).toBe("20.11 21:26");
  });
  it("a rejected version: «отклонено вами 21:20», the time from the journal", () => {
    const q = { id: 4, pluginId: "p", version: "0.0.9", lastSeen: at(20, 0) };
    const ev = [
      { ts: at(21, 20), kind: "dismissed", pluginId: "p", detail: { review: 4, version: "0.0.9" } },
      { ts: at(21, 10), kind: "dismissed", pluginId: "other", detail: { review: 4 } },
    ];
    expect(rejectedByText(rejectedAtOf(q, ev), now)).toBe("отклонено вами 21:20");
    expect(rejectedAtOf(q, [])).toBe(q.lastSeen);
  });
  it("a rejected change of the agents' files says when and by which button", () => {
    expect(app).toContain("кнопкой «Это не я»");
    expect(app).toMatch(/принято вами/);
  });
});

describe("9. «Вернуть» only where it can work; errors in Russian", () => {
  it("no button for a version whose files changed", () => {
    expect(canRestore({ reason: "каталог плагина не совпал с хешем запроса", contentHash: "h" })).toBe(false);
    expect(canRestore({ reason: null, contentHash: null })).toBe(false);
    expect(canRestore({ reason: "отклонено вами", contentHash: "h" })).toBe(true);
  });
  it("the guard's English is a Russian sentence, never `acknowledgeBlock`", () => {
    const raw = "the directory's hash did not match the request's: this version is never approved, with or without acknowledgeBlock (reinstall the plugin from its source)";
    const text = humanError(raw);
    expect(text).toMatch(/Установите плагин заново/);
    expect(text).not.toMatch(/acknowledgeBlock|hash|directory/);
    expect(humanError("invalid or expired session")).toMatch(/Сессия закрылась/);
    expect(humanError("something nobody foresaw: EINVAL")).not.toMatch(/[A-Za-z]{4}/);
    expect(humanError("Защита сказала по-русски")).toBe("Защита сказала по-русски");
  });
});

describe("10. one count for alarms", () => {
  it("an alarm is counted per change: the banner and the line agree", () => {
    const status = pageStatus({
      guardDown: false,
      red: [],
      yellow: [],
      alarms: [{ anchor: "sbb-agents", tab: "status", text: "Настройки агентов: критичных изменений — 2", weight: 2 }],
    });
    expect(status.count).toBe(2);
    expect(status.label).toBe("Требует внимания (2)");
    expect(awayAlarms([{ anchor: "a", tab: "status", text: "t", weight: 2 }])!.title).toBe("2 тревоги системы");
    expect(alarmCount([{ weight: 2 }, {}])).toBe(3);
    expect(awayAlarms([])).toBeNull();
  });
});
