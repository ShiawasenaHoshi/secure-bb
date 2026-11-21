// Round 5 (items 2–8): one card per version, files in plain words, details that match the colour, a page that holds still, one set of counts.
import { chmodSync, cpSync, mkdtempSync, readdirSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { runChecks, type CheckResult } from "../src/checks/index.js";
import { createDrafts, DRAFT_TTL_MS } from "../src/drafts.js";
import {
  checksSummary, countsLine, decisionOf, deferKey, DELETE_CONFIRM_BUTTONS, dropShadowedLocal, dropUnstamped, hasMark, hasNoGuardRecord, layoutItems, makeDeferStub, MIN_STUB_HEIGHT,
  NO_RECORD_HEADLINE, NO_RECORD_LINE, pageCounts, planCards, restoreNote, RESTORE_FRESH_CODE, riskHeadline, significantFindings, stableOrder, stampMark, capsWithPaths, withoutMark,
} from "../src/ux.js";

const FIXTURES = new URL("./fixtures/", import.meta.url).pathname;
const scratch = realpathSync(mkdtempSync(join(tmpdir(), "sbb-r5-")));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));
function normalise(dir: string): void {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) {
      chmodSync(p, 0o755);
      normalise(p);
    } else if (e.isFile()) chmodSync(p, 0o644);
  }
}
let n = 0;
async function fixture(name: string): Promise<CheckResult> {
  const dir = join(scratch, `f${n++}-${name}`);
  cpSync(join(FIXTURES, name), dir, { recursive: true });
  chmodSync(dir, 0o755);
  normalise(dir);
  return runChecks(dir);
}
const headline = (r: CheckResult) => riskHeadline(capsWithPaths(r), r.findings.filter((f) => f.severity === "review").map((f) => f.rule));

describe("2. one version, one card", () => {
  const guardEntry = { pluginId: "agent-traces", version: "1.0.0" };
  it("a page-side record of a version the guard has an entry for is dropped", () => {
    const local = [
      { pluginId: "agent-traces", version: "1.0.0", id: -4 },
      { pluginId: "agent-traces", version: "1.0.1", id: -5 },
      { pluginId: "other", version: "1.0.0", id: -6 },
    ];
    expect(dropShadowedLocal([guardEntry], local).map((x) => x.id)).toEqual([-5, -6]);
    expect(dropShadowedLocal([], local)).toHaveLength(3);
  });
  it("a record with no core hash is a card that cannot enable anything: no green, one reason, one fix", () => {
    expect(hasNoGuardRecord({ kind: "afterfact", contentHash: null })).toBe(true);
    expect(hasNoGuardRecord({ kind: "afterfact", contentHash: "abc" })).toBe(false);
    expect(hasNoGuardRecord({ kind: "proposal", contentHash: null })).toBe(false); // not installed yet: approving it installs it
    expect(hasNoGuardRecord({ kind: "hook", contentHash: "abc" })).toBe(false);
    expect(NO_RECORD_HEADLINE).not.toMatch(/Безопасно|можно включить/);
    expect(NO_RECORD_LINE).toMatch(/bb secure-bb propose/);
    expect(NO_RECORD_LINE).not.toMatch(/хеш ядра|позовите/);
  });
});

describe("3. files without known paths are not «your documents»", () => {
  it("a file read by a path the code does not name: neutral, yellow", async () => {
    const r = await fixture("fs-unknown");
    expect(r.capabilities.find((c) => c.kind === "fs")!.detail).not.toContain("home");
    expect(headline(r)).toEqual({ level: "caution", text: "Работает с файлами (какими — из кода не видно)" });
  });
  it("the home directory in the code: your documents", async () => {
    const r = await fixture("fs-home");
    expect(r.capabilities.find((c) => c.kind === "fs")!.detail).toContain("home");
    expect(headline(r)).toEqual({ level: "danger", text: "Может читать и менять ваши документы" });
  });
});

describe("4. the details say what the colour says", () => {
  const f = (rule: string, severity: string, file = "a.js", line = 1) => ({ rule, severity, file, line });
  it("only what matters, in Russian; no «not scanned», no raw rule names", () => {
    const lines = significantFindings([f("invisible-chars", "block"), f("dynamic-access", "review", "b.js", 3), f("dynamic-access", "review", "b.js", 9), f("ignored-findings", "info"), f("unreachable-files", "info"), f("parse-note", "info"), f("some-new-rule", "review")]);
    expect(lines.map((l) => l.text)).toEqual([
      "В коде плагина спрятаны невидимые символы",
      "Код обращается к функциям по имени, собранному на лету: что именно он вызывает, из кода не видно",
      "Проверка нашла особенность в коде",
    ]);
    expect(lines[1]!.count).toBe(2);
    expect(JSON.stringify(lines)).not.toMatch(/not scanned|invisible-chars|dynamic-access|ignored-findings/);
  });
  it("info only: nothing to show, and the summary says so", () => {
    const lines = significantFindings([f("ignored-findings", "info"), f("dep-content-unverified", "info")]);
    expect(lines).toEqual([]);
    expect(checksSummary(lines, 2)).toBe("Проверки: значимых находок нет · возможностей: 2");
  });
  it("72 findings of zod's tests do not become «72 находок» on the card", () => {
    const many = Array.from({ length: 72 }, (_, i) => f("ignored-findings", "info", "node_modules/zod", i));
    expect(checksSummary(significantFindings(many), 1)).toContain("значимых находок нет");
  });
  it("a yellow card that sends to the details sends to a fold that is there, and open", () => {
    const r = riskHeadline([{ kind: "ui", detail: [] }], ["dynamic-access"]);
    expect(r.level).toBe("caution");
    expect(r.look).toBe(true);
    expect(r.text).toContain("«Технических подробностях»");
    expect(r.text).not.toContain("откройте «Подробнее»");
    // and a safe one does not send anywhere
    expect(riskHeadline([{ kind: "ui", detail: [] }], []).look).toBeUndefined();
  });
});

describe("5. «Решить позже» leaves a stub, the delete question holds its place", () => {
  const q = { id: 7, pluginId: "aura", version: "0.2.10", contentHash: "h" };
  it("the stub is as tall as the card and says what was put aside", () => {
    const s = makeDeferStub(q, 321.4);
    expect(s).toMatchObject({ key: "aura", text: "Отложено: aura 0.2.10", height: 321, restore: { id: 7, pluginId: "aura" } });
    expect(makeDeferStub(q, 10).height).toBe(MIN_STUB_HEIGHT);
    expect(makeDeferStub(q, Number.NaN).height).toBe(MIN_STUB_HEIGHT);
  });
  it("the stub stands where the card stood: the neighbours do not move", () => {
    const first = stableOrder(null, ["a", "aura", "b"]);
    // the card «aura» was put aside: it is no longer among the active ones, its stub keeps the place
    const stub = makeDeferStub(q, 200);
    const next = stableOrder(first.order, ["a", "b"], [stub.key]);
    expect(next.order).toEqual(["a", "aura", "b"]);
    expect(layoutItems(next.order, new Set(["a", "b"]), [stub]).map((i) => (i.stub ? `stub:${i.key}` : i.key))).toEqual(["a", "stub:aura", "b"]);
  });
  it("the question buttons are always «Да, удалить», «Нет», in this order", () => {
    expect([...DELETE_CONFIRM_BUTTONS]).toEqual(["Да, удалить", "Нет"]);
  });
});

describe("6. a typed code survives a refresh", () => {
  it("kept by the card's id, given back to a card that is built again", () => {
    const d = createDrafts();
    d.set("card:aura@0.2.10#h", "123");
    d.set("card:chime@0.1.0#g", "456");
    expect(d.get("card:aura@0.2.10#h")).toBe("123");
    expect(d.get("card:chime@0.1.0#g")).toBe("456");
    expect(d.get("card:other")).toBe("");
  });
  it("a stale draft is not given back; clearing and an empty value forget it", () => {
    const d = createDrafts();
    d.set("k", "123456", 1_000);
    expect(d.get("k", 1_000 + DRAFT_TTL_MS)).toBe("123456");
    expect(d.get("k", 1_000 + DRAFT_TTL_MS + 1)).toBe("");
    d.set("k", "1", 5);
    d.set("k", "", 6);
    expect(d.get("k", 7)).toBe("");
    d.set("k", "9", 8);
    d.clear("k");
    expect(d.get("k", 9)).toBe("");
  });
});

describe("7. the numbers agree, and «отложено» is what the person put aside", () => {
  const e = (id: number, pluginId: string, firstSeen = 100) => ({ id, pluginId, version: "1.0.0", contentHash: `h${id}`, firstSeen });
  const key = (x: ReturnType<typeof e>) => deferKey(x.pluginId, x.contentHash, x.id);
  it("all counts come from one plan and add up", () => {
    const held = [e(1, "a"), e(2, "b"), e(3, "c"), e(4, "d"), e(5, "e")];
    const plan = planCards(held, { deferred: [stampMark(key(held[1]!), 500)], kept: [stampMark(key(held[2]!), 500)] });
    const c = pageCounts(plan, 2, 1);
    expect(c).toMatchObject({ waiting: 3, deferred: 1, kept: 1, alarms: 2, attention: 6, quarantine: 6 });
    expect(c.attention).toBe(c.waiting + c.deferred + c.alarms);
    expect(c.quarantine).toBe(c.waiting + c.deferred + c.kept + 1);
    expect(countsLine(c)).toBe("Из чего число: ждут вас: 3 · отложено вами: 1 · тревог: 2.");
    expect(countsLine(pageCounts(planCards([e(1, "a")], { deferred: [], kept: [] }), 0, 0))).toBe("");
  });
  it("a mark made before the entry appeared is about an earlier data set: not deferred", () => {
    const x = e(1, "a", 1_000);
    expect(decisionOf(x, { deferred: [stampMark(key(x), 500)], kept: [] })).toBe("open");
    expect(decisionOf(x, { deferred: [stampMark(key(x), 1_500)], kept: [] })).toBe("deferred");
    expect(decisionOf(x, { deferred: [], kept: [stampMark(key(x), 500)] })).toBe("open");
  });
  it("plain marks of an older page still work in the pure code, and are dropped when the page loads", () => {
    const x = e(1, "a");
    expect(decisionOf(x, { deferred: [key(x)], kept: [] })).toBe("deferred");
    expect(dropUnstamped([key(x), stampMark(key(x), 5)])).toEqual([stampMark(key(x), 5)]);
  });
  it("marks are replaced, not stacked", () => {
    const x = e(1, "a");
    const list = [stampMark(key(x), 1), stampMark("other", 2)];
    expect(withoutMark(list, key(x))).toEqual([stampMark("other", 2)]);
    expect(hasMark(list, key(x))).toBe(true);
    expect(hasMark(withoutMark(list, key(x)), key(x))).toBe(false);
  });
});

describe("8. restoring while a session is open", () => {
  it("says a fresh code is needed", () => {
    expect(restoreNote(true)).toBe(RESTORE_FRESH_CODE);
    expect(RESTORE_FRESH_CODE).toMatch(/свежий код: меняются файлы агента/i);
    expect(restoreNote(false)).toBeNull();
  });
});
