// The design pass of the page: every thing once, the level of a card, its rights as rows, the header's one line, and no colors outside the theme.
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { cardLevel, LEVEL_LABEL, NETWORK_UNRELATED_NOTE, permissionList, VISIBLE_ROWS, whyLine } from "../src/cardview";
import { headerLine, quietAwayGroups, SECOND_FACTOR_ANCHOR, splitAlarms } from "../src/pageview";
import { factorOfApproval, factorWords, truthfulApproval } from "../src/factor";
import { groupAway, type AwayEvent, type CapLike, type ProblemRef } from "../src/ux";

const NOW = 1_800_000_000_000;
const ev = (kind: string, pluginId: string, minAgo: number, detail: unknown = null): AwayEvent => ({ ts: NOW - minAgo * 60_000, kind, pluginId, threadId: null, detail, from: "plugin" });

describe("«Пока вас не было»: every thing once", () => {
  const events = [ev("hold", "chime", 30), ev("hold", "notify", 29), ev("approved.source", "figma-sync", 20), ev("approved.source", "figma-sync", 19), ev("reject", "old-theme", 10), ev("dismissed", "junk", 5)];
  const waiting = { chime: { yellow: 1, red: 0 }, notify: { yellow: 0, red: 1 } };

  it("the plain summary does say that versions wait (that is why the page must not show it)", () => {
    const texts = groupAway(events, 0, false, waiting).map((g) => g.text).join("\n");
    expect(texts).toMatch(/chime: 1 версия ждёт вашего решения/);
    expect(texts).toMatch(/notify: 1 остановлена/);
  });

  it("a version that waits (yellow) or is stopped (red) is not in the quiet summary; what passed, was rejected or deleted is", () => {
    const quiet = quietAwayGroups(groupAway(events, 0, false, waiting));
    const texts = quiet.map((g) => g.text).join("\n");
    expect(texts).not.toMatch(/chime|notify/);
    expect(texts).not.toMatch(/ждёт|ждут|остановлен/);
    expect(texts).toMatch(/2 версии figma-sync прошли сами/);
    expect(texts).toMatch(/old-theme: 1 отклонена/);
    expect(texts).toMatch(/1 версия junk удалена/);
  });

  it("a plugin that both passed a version and now waits keeps the line of the first and loses the second", () => {
    const mixed = [ev("approved.source", "chime", 40), ev("hold", "chime", 30)];
    const quiet = quietAwayGroups(groupAway(mixed, 0, false, { chime: { yellow: 1, red: 0 } }));
    expect(quiet.map((g) => g.text)).toEqual(["1 версия chime прошла сама"]);
  });
});

describe("the header says one thing", () => {
  const first: ProblemRef = { anchor: "sbb-card-1", tab: "status", text: "auto-answer 0.1.0" };
  const quiet = { level: "ok" as const, first: null };
  it("nothing to do → «Всё под защитой», no button", () => {
    expect(headerLine({ status: quiet, waiting: 0, deferred: 0, alarms: [] })).toEqual({ tone: "ok", text: "Всё под защитой", target: null, action: null });
  });
  it("waiting versions → «Ждут вашего решения: N» and one button to the first; it is not an alarm", () => {
    const h = headerLine({ status: { level: "attention", first }, waiting: 3, deferred: 0, alarms: [] });
    expect(h).toMatchObject({ tone: "waiting", text: "Ждут вашего решения: 3", target: first, action: "К решению" });
  });
  it("a real alarm → «Тревога: …»", () => {
    const alarm: ProblemRef = { anchor: "sbb-guard-alarm", tab: "status", text: "Журнал сторожа нарушен" };
    expect(headerLine({ status: { level: "attention", first: alarm }, waiting: 2, deferred: 0, alarms: [alarm] })).toMatchObject({ tone: "alarm", text: "Тревога: Журнал сторожа нарушен" });
  });
  it("no second factor is the state of the header, and the first thing to do — before the other alarms; no alarm is turned down to a calm line", () => {
    const other: ProblemRef = { anchor: "sbb-guard-alarm", tab: "status", text: "Журнал сторожа нарушен" };
    const noFactor: ProblemRef = { anchor: SECOND_FACTOR_ANCHOR, tab: "more", text: "Второй фактор не настроен" };
    const h = headerLine({ status: { level: "attention", first: other }, waiting: 2, deferred: 0, alarms: [other, noFactor] });
    expect(h).toEqual({ tone: "alarm", text: "Настройте второй фактор: без него ничего нельзя подтвердить", target: noFactor, action: "Настроить" });
    expect(headerLine({ status: { level: "attention", first: noFactor }, waiting: 0, deferred: 0, alarms: [noFactor] }).tone).toBe("alarm");
    expect(splitAlarms([other, noFactor])).toEqual({ critical: [other, noFactor], calm: [] });
  });
  it("the guard down and a stopped plugin are alarms", () => {
    expect(headerLine({ status: { level: "down", first }, waiting: 0, deferred: 0, alarms: [] }).tone).toBe("alarm");
    expect(headerLine({ status: { level: "stopped", first }, waiting: 1, deferred: 0, alarms: [] })).toMatchObject({ tone: "alarm", text: "Тревога: остановлен плагин — auto-answer 0.1.0" });
  });
});

describe("the card of a version", () => {
  const read = (flowVerdict: "nowhere" | "leaves" | "unknown"): CapLike => ({ kind: "sdk_read", detail: [], flow: { source: "threads", detail: [], verdict: flowVerdict, sinks: flowVerdict === "leaves" ? [{ kind: "network", target: "stats.example" }] : [] } });
  const net: CapLike = { kind: "network", detail: ["host:stats.example"] };

  it("the levels: red or a dangerous headline → «Опасно», a caution → «Нужна проверка», safe → «Только оформление»", () => {
    expect(cardLevel({ red: true, risk: { level: "caution" } })).toBe("danger");
    expect(cardLevel({ red: false, risk: { level: "danger" } })).toBe("danger");
    expect(cardLevel({ red: false, risk: { level: "caution" } })).toBe("check");
    expect(cardLevel({ red: false, risk: { level: "safe" } })).toBe("calm");
    expect(LEVEL_LABEL).toEqual({ danger: "Опасно", check: "Нужна проверка", calm: "Только оформление" });
  });

  it("rights are rows with a short label and a muted detail, in the order: what can be got at, what it does, the looks", () => {
    const l = permissionList([{ kind: "ui", detail: [] }, read("nowhere"), { kind: "sdk_send", detail: [] }], false);
    // what can be got at first, then what it does, the looks last
    expect(l.rows.map((r) => r.kind)).toEqual(["sdk_read", "sdk_send", "ui"]);
    const reads = l.rows.find((r) => r.kind === "sdk_read")!;
    expect(reads.label).toBe("Читает ваши переписки в bb");
    expect(reads.detail).toMatch(/никуда не отправляет/);
    expect(l.rows.find((r) => r.kind === "sdk_send")!.danger).toBe(true);
  });

  it("no more than five rows are visible, the rest is «ещё N»", () => {
    const caps: CapLike[] = ["ui", "http_routes", "sdk_meta", "sdk_questions", "sdk_read", "network", "fs"].map((kind) => ({ kind, detail: [] }));
    const l = permissionList(caps, false);
    expect(l.visible).toHaveLength(VISIBLE_ROWS);
    expect(l.more).toHaveLength(caps.length - VISIBLE_ROWS);
  });

  // What the chime plugin showed: the network first and the conversations under «ещё 4».
  const chime: CapLike[] = [
    { kind: "network", detail: ["unresolved-host"] },
    { kind: "child_process", detail: ["afplay"], programs: ["afplay"] },
    { kind: "env", detail: ["env:NODE_ENV"] },
    { kind: "fs", detail: [] },
    { kind: "ui", detail: [] },
    { kind: "sdk_meta", detail: [] },
    { kind: "sdk_questions", detail: [], flow: { source: "questions", detail: [], verdict: "nowhere", sinks: [] } },
    { kind: "sdk_read", detail: [], flow: { source: "threads", detail: [], verdict: "nowhere", sinks: [] } },
  ];

  it("a chime-like set: the conversations and the questions of agents come before the network and the programs; the looks are last", () => {
    const l = permissionList(chime, false);
    const kinds = l.rows.map((r) => r.kind);
    expect(kinds.slice(0, 2)).toEqual(["sdk_questions", "sdk_read"].sort((a, b) => kinds.indexOf(a) - kinds.indexOf(b)));
    expect(kinds.indexOf("sdk_read")).toBeLessThan(kinds.indexOf("network"));
    expect(kinds.indexOf("sdk_read")).toBeLessThan(kinds.indexOf("child_process"));
    expect(kinds.indexOf("sdk_questions")).toBeLessThan(kinds.indexOf("network"));
    expect(kinds[kinds.length - 1]).toBe("ui");
    // the conversations are among the visible rows, the looks are under «ещё»
    expect(l.visible.map((r) => r.kind)).toContain("sdk_read");
    expect(l.more.map((r) => r.kind)).toContain("ui");
  });

  it("a right of the level «Опасно» is never under «ещё N», however many rights there are", () => {
    const caps: CapLike[] = [...["sdk_read", "sdk_questions", "credentials", "sdk_meta", "http_routes", "contribute_env", "host_artifact", "dynamic_code", "network", "fs"].map((kind) => ({ kind, detail: [] })), { kind: "sdk_answer", detail: [] }, { kind: "sdk_send", detail: [] }, { kind: "sdk_agents", detail: [] }, { kind: "sdk_settings", detail: [] }];
    const l = permissionList(caps, false);
    const dangerous = l.rows.filter((r) => r.danger);
    // the three valuables stand first, so the dangerous ones start after the third row and two of them are beyond the fifth
    expect(l.rows.findIndex((r) => r.danger)).toBeGreaterThanOrEqual(3);
    expect(l.rows.map((r) => r.danger).lastIndexOf(true)).toBeGreaterThanOrEqual(5);
    expect(dangerous.length).toBeGreaterThanOrEqual(4);
    for (const r of dangerous) expect(l.visible).toContain(r);
    expect(l.more.some((r) => r.danger)).toBe(false);
    // the rows are the same rows: nothing is lost, nothing is twice
    expect([...l.visible, ...l.more].sort((a, b) => a.kind.localeCompare(b.kind))).toEqual([...l.rows].sort((a, b) => a.kind.localeCompare(b.kind)));
  });

  it("the caveat «сеть есть, с прочитанным не связана» is one muted line, only when what is read goes nowhere", () => {
    expect(permissionList([read("nowhere"), net], false).networkNote).toBe(NETWORK_UNRELATED_NOTE);
    expect(permissionList([read("unknown"), net], false).networkNote).toBeNull();
    expect(permissionList([read("leaves"), net], false).networkNote).toBeNull();
    expect(permissionList([read("nowhere")], false).networkNote).toBeNull();
  });

  it("the one line of why: the author's words (marked), else the purposes the checks found, else the reason it waits", () => {
    expect(whyLine({ authorWhy: "Звук при ответе", caps: [], reasonLine: "Плагин из места. Он сможет: …" })).toEqual({ text: "Звук при ответе", byAuthor: true });
    expect(whyLine({ authorWhy: null, caps: [{ kind: "sdk_read", detail: [], purpose: ["показывает счётчик на своей странице"] }], reasonLine: "x" }).text).toBe("Показывает счётчик на своей странице.");
    expect(whyLine({ authorWhy: null, caps: [], reasonLine: "Плагин из места, которое вы раньше не отмечали (github.com/o/r). Он сможет: читать. Пока вы не решите, он не запускается." })).toEqual({ text: "Плагин из места, которое вы раньше не отмечали (github.com/o/r).", byAuthor: false });
  });
});

describe("«чем подтверждено» says how it was confirmed", () => {
  const recent = [
    { kind: "approved.touch", detail: { approval: 5, via: "totp" } },
    { kind: "approved.touch", detail: { approval: 6, via: "passkey", key: "MacBook" } },
    { kind: "approved.trust", detail: { approval: 7, via: "session", session: 1 } },
  ];
  const touch = (id: number, why: string | null = "касанием: источник нельзя назвать своим") => ({ id, via: "touch", why });
  const guard = { guardMode: true, recent };

  it("reads the factor from the guard's journal", () => {
    expect(factorOfApproval(5, recent)).toEqual({ via: "totp" });
    expect(factorOfApproval(6, recent)).toEqual({ via: "passkey", key: "MacBook" });
    expect(factorOfApproval(99, recent)).toBeNull();
    expect([factorWords({ via: "totp" }), factorWords({ via: "passkey", key: "MacBook" }), factorWords({ via: "passkey" }), factorWords({ via: "session" })]).toEqual(["кодом", "касанием (ключ MacBook)", "касанием", "в открытой сессии"]);
  });
  it("a version approved with a code says «кодом», not «касанием»", () => {
    expect(truthfulApproval(touch(5), guard).why).toBe("вы, кодом: источник нельзя назвать своим");
    expect(truthfulApproval(touch(5, null), guard).why).toBe("вы, кодом");
  });
  it("a key says which key", () => {
    expect(truthfulApproval(touch(6), guard).why).toBe("вы, касанием (ключ MacBook): источник нельзя назвать своим");
  });
  it("a session is said as a session", () => {
    expect(truthfulApproval(touch(7, "касанием"), guard).why).toBe("вы, в открытой сессии");
  });
  it("where the journal has no record it does not claim a touch", () => {
    expect(truthfulApproval(touch(99), guard).why).toBe("вы подтвердили: источник нельзя назвать своим");
    expect(truthfulApproval(touch(99), guard).why).not.toMatch(/касани/);
  });
  it("without a guard the confirmation of the plugin's own gate is a code", () => {
    expect(truthfulApproval(touch(1), { guardMode: false, recent: [] }).why).toBe("вы, кодом: источник нельзя назвать своим");
  });
  it("what the person did not confirm keeps its words (a window, a source, a pin)", () => {
    for (const via of ["window", "source", "pin", "auto"]) {
      const a = { id: 5, via, why: "прошла сама: свой источник" };
      expect(truthfulApproval(a, guard)).toBe(a);
    }
  });
});

describe("no colors outside the theme", () => {
  // The page's own sources and the vendored components: tokens only (bg-card, text-muted-foreground, border-border, text-destructive, …).
  const root = fileURLToPath(new URL("..", import.meta.url));
  const files = (dir: string): string[] =>
    readdirSync(join(root, dir)).flatMap((n) => {
      const p = join(dir, n);
      return statSync(join(root, p)).isDirectory() ? files(p) : /\.(tsx?|css)$/.test(n) ? [p] : [];
    });
  const sources = ["app.tsx", ...files("app"), ...files("components"), ...files("lib"), ...files("hooks")];
  // The one translucent-black dim behind a dialog is in lib/scrim.ts; everything else is a token.
  const bypass = /amber-|red-|yellow-|green-|blue-|bg-black|bg-white|rgba?\((?!0 0 0 \/ 0\.4\))|(?:slate|gray|zinc|stone|neutral|orange|lime|emerald|teal|cyan|sky|indigo|violet|purple|fuchsia|pink|rose)-\d{2,3}|#[0-9a-f]{3,6}\b|oklch\(/i;

  it("the page's sources hold no palette color, hex or oklch", () => {
    expect(sources.length).toBeGreaterThan(20);
    const hits = sources.flatMap((f) => readFileSync(join(root, f), "utf8").split("\n").map((l, i) => ({ f, i: i + 1, l })).filter(({ l }) => bypass.test(l)).map(({ f: file, i, l }) => `${file}:${i}: ${l.trim().slice(0, 100)}`));
    expect(hits).toEqual([]);
  });

  it("the test sees a violation (it does not pass for lack of looking)", () => {
    for (const bad of ["bg-red-50", "text-amber-700", "border-yellow-500/60", "text-green-800", "fill-[#fff]", "bg-[oklch(0.7_0.1_20)]", "dark:bg-blue-950"]) expect(bypass.test(bad), bad).toBe(true);
    for (const ok of ["bg-card", "text-muted-foreground", "border-border", "text-destructive", "bg-muted"]) expect(bypass.test(ok), ok).toBe(false);
  });
});
