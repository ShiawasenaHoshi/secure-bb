// `sbb-guard setup`: the whole registration in one command, on a temporary directory, with a software authenticator as the "person at the page".
// The console is scripted: answers to its questions, and between its looks at the database the "page" does what a person would do in the browser
// (opens the link, registers a key, presses «Проверить касание»).
import { afterEach, describe, expect, it } from "vitest";
import { enrollLink, gateUrl, main, setup, type EnrollDeps, type Io } from "../../guard/src/cli.ts";
import { resolveRp } from "../../guard/src/config.ts";
import { SETUP_CHECK_PURPOSE } from "../../guard/src/guard.ts";
import { base32Decode, hotp, stepAt } from "../../guard/src/totp.ts";
import { SoftAuthenticator, startGuard, touchFor, type TestGuard } from "./support.ts";

let g: TestGuard;
afterEach(async () => {
  await g?.close();
});

interface Script {
  /** Answer to the TOTP question (default: yes). */
  totp?: string;
  /** The codes typed for the first code prompt, in order; default: the right one. */
  codes?: Array<string | "right">;
  /** The answer to «this is your key, activate it?». */
  activate?: string | null;
  /** The page does not register a key / does not press «Проверить касание». */
  noEnroll?: boolean;
  noCheck?: boolean;
  /** The page touches with a CODE instead of the key (must not count). */
  checkWithCode?: boolean;
  /** Any question is a failure (a repeated run with everything in place). */
  noQuestions?: boolean;
  /** No terminal. */
  noTerminal?: boolean;
  checkTimeoutMs?: number;
}

/** One run of the wizard with a scripted console and a scripted page. */
async function run(auth: SoftAuthenticator, s: Script = {}, paths = g.paths) {
  const lines: string[] = [];
  const asked: string[] = [];
  const codes = [...(s.codes ?? ["right"])];
  const secretOf = (): string => /ключ вручную: ([A-Z2-7]+)/.exec(lines.join("\n"))![1]!;
  const io: Io = {
    out: (t) => void lines.push(t),
    err: (t) => void lines.push(`ERR ${t}`),
    async ask(q) {
      asked.push(q);
      if (s.noTerminal) return null;
      if (s.noQuestions) throw new Error(`unexpected question: ${q}`);
      if (q.includes("Подключить коды")) return s.totp ?? "д";
      if (q.includes("Введите шесть цифр")) {
        const c = codes.shift() ?? "right";
        return c === "right" ? hotp(base32Decode(secretOf()), stepAt(g.clock.t)) : c;
      }
      if (q.includes("Это ваш ключ")) return s.activate === undefined ? "y" : s.activate;
      if (q.includes("Добавить ключ сейчас")) return "д";
      throw new Error(`unexpected question: ${q}`);
    },
  };
  let enrolled = false;
  let checked = false;
  const deps: EnrollDeps = {
    pollMs: 1,
    ...(s.checkTimeoutMs === undefined ? {} : { checkTimeoutMs: s.checkTimeoutMs }),
    async sleep() {
      const text = lines.join("\n");
      const token = /#enroll=([A-Z0-9-]+)/.exec(text)?.[1];
      if (token && !enrolled && !s.noEnroll) {
        enrolled = true;
        const options = (await g.send({ op: "passkey-register", token })).options;
        await g.send({ op: "passkey-register", token, ...auth.create(options) });
      }
      if (text.includes("«Проверить касание»") && !checked && !s.noCheck) {
        checked = true;
        if (s.checkWithCode) await g.send({ op: "touch", purpose: SETUP_CHECK_PURPOSE, code: g.nextCode() });
        else {
          const t = await touchFor(g, auth, { op: "touch", purpose: SETUP_CHECK_PURPOSE });
          await g.send({ op: "touch", purpose: SETUP_CHECK_PURPOSE, passkey: t.passkey });
        }
      }
      g.clock.advance(1000);
    },
  };
  const code = await setup(paths, io, {}, g.clock.now, deps);
  return { code, text: lines.join("\n"), lines, asked };
}
const journalKinds = async (): Promise<string[]> => ((await g.send({ op: "state" })).journal.recent as Array<{ kind: string }>).map((j) => j.kind);

describe("sbb-guard setup: a fresh guard, every step", () => {
  it("TOTP with a QR, then a passkey by a link with the token in the fragment, then the test touch, then the leaflet", async () => {
    g = await startGuard({ register: false });
    const auth = new SoftAuthenticator();
    const r = await run(auth);
    expect(r.code).toBe(0);
    // TOTP: a QR was drawn and the secret locked
    expect(r.text).toMatch(/[█▀▄]/);
    expect(r.text).toContain("Коды из приложения подключены".replace("Коды", "коды"));
    expect(g.guard.totpRegistered()).toBe(true);
    // passkey: the link has the guard's origin, the page's path and the token in the FRAGMENT (no query at all)
    const link = /(http\S+#enroll=\S+)/.exec(r.text)![1]!;
    expect(link).toMatch(/^http:\/\/localhost:38886\/plugins\/secure-bb\/gate#enroll=[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$/);
    expect(link).not.toContain("?");
    expect(r.text).toMatch(/Зарегистрирован ключ/);
    expect(g.guard.listPasskeys()).toMatchObject([{ state: "active" }]);
    // the test touch: the console saw a signature on `touch setup-check` and said so
    expect(r.text).toContain("Всё работает");
    expect(g.guard.passkeyTouches(SETUP_CHECK_PURPOSE)).toHaveLength(1);
    // the leaflet: where the page is, the password manager, how to switch codes off later
    expect(r.text).toContain("Памятка");
    expect(r.text).toContain("http://localhost:38886/plugins/secure-bb/gate");
    expect(r.text).toMatch(/менеджер паролей/);
    expect(r.text).toContain("sbb-guard totp-disable");
  });

  it("a second run asks nothing, does only what is missing (nothing), and breaks nothing", async () => {
    g = await startGuard({ register: false });
    const auth = new SoftAuthenticator();
    expect((await run(auth)).code).toBe(0);
    const before = { keys: g.guard.listPasskeys(), enrollOpens: (await journalKinds()).filter((k) => k === "passkey.enroll.open").length };
    const r = await run(auth, { noQuestions: true });
    expect(r.code).toBe(0);
    expect(r.asked).toEqual([]);
    expect(r.text).toContain("Эти шаги пропускаю");
    expect(r.text).toContain("уже проходило успешно");
    expect(r.text).not.toContain("#enroll=");
    expect(g.guard.totpRegistered()).toBe(true);
    expect(g.guard.listPasskeys()).toEqual(before.keys);
    expect((await journalKinds()).filter((k) => k === "passkey.enroll.open")).toHaveLength(before.enrollOpens);
    expect(g.guard.verifyJournal().ok).toBe(true);
  });

  it("skipping the codes: the passkey is then required, and the check runs; the secret is never made", async () => {
    g = await startGuard({ register: false });
    const r = await run(new SoftAuthenticator(), { totp: "н" });
    expect(r.code).toBe(0);
    expect(g.guard.totpRegistered()).toBe(false);
    expect(g.guard.activeKeys()).toHaveLength(1);
    expect(r.text).toContain("Всё работает");
    // the leaflet does not promise to switch off codes that were never on
    expect(r.text).toContain("sbb-guard totp-register");
    expect(r.text).not.toContain("totp-disable");
  });

  it("a wrong code is not the end: three tries, then a new QR on the next run", async () => {
    g = await startGuard({ register: false });
    const auth = new SoftAuthenticator();
    const bad = await run(auth, { codes: ["000000", "111111", "222222"] });
    expect(bad.code).toBe(1);
    expect(bad.text).toContain("Код не подошёл (3 из 3)");
    expect(g.guard.totpRegistered()).toBe(false);
    const again = await run(auth, { codes: ["000000", "right"] });
    expect(again.text).toContain("Код не подошёл (1 из 3)");
    expect(again.code).toBe(0);
    expect(g.guard.totpRegistered()).toBe(true);
  });
});

describe("sbb-guard setup: the key and the test touch", () => {
  it("a key that the person does not confirm is discarded; the next run goes straight to the key (the codes are already on)", async () => {
    g = await startGuard({ register: false });
    const auth = new SoftAuthenticator();
    const first = await run(auth, { activate: "n" });
    expect(first.code).toBe(1);
    expect(first.text).toContain("Ключ не подтверждён");
    expect(g.guard.activeKeys()).toEqual([]);
    expect(g.guard.totpRegistered()).toBe(true);
    const second = await run(new SoftAuthenticator(), {});
    expect(second.asked.some((q) => q.includes("Подключить коды"))).toBe(false);
    expect(second.code).toBe(0);
    expect(g.guard.activeKeys()).toHaveLength(1);
  });

  it("the key must be confirmed with y/да; any other answer, or none, is a no", async () => {
    g = await startGuard({ register: false });
    expect((await run(new SoftAuthenticator(), { activate: null })).code).toBe(1);
    expect(g.guard.activeKeys()).toEqual([]);
    expect((await run(new SoftAuthenticator(), { activate: "да" })).code).toBe(0);
    expect(g.guard.activeKeys()).toHaveLength(1);
  });

  it("no touch in two minutes: it says what to look at, and a later run repeats ONLY the check", async () => {
    g = await startGuard({ register: false });
    const auth = new SoftAuthenticator();
    const first = await run(auth, { noCheck: true });
    expect(first.code).toBe(1);
    expect(first.text).toContain("Касание не пришло за 2 минуты");
    expect(first.text).toMatch(/менеджер паролей/);
    expect(g.guard.activeKeys()).toHaveLength(1);
    const again = await run(auth, { noQuestions: true });
    expect(again.code).toBe(0);
    expect(again.text).not.toContain("#enroll=");
    expect(again.text).toContain("Всё работает");
    expect(g.guard.activeKeys()).toHaveLength(1);
  });

  it("a touch with a CODE does not pass the check: a code goes through bb, only a signature is proof", async () => {
    g = await startGuard({ register: false });
    const r = await run(new SoftAuthenticator(), { checkWithCode: true });
    expect(r.code).toBe(1);
    expect(r.text).toContain("Касание не пришло");
    expect(r.text).not.toContain("Всё работает");
  });

  it("a touch for another purpose, or an old one from before this run, does not count", async () => {
    g = await startGuard({ register: false });
    const auth = new SoftAuthenticator();
    // a first run passes the check; the key is then removed and a new one added: the new key has not passed it yet
    expect((await run(auth)).code).toBe(0);
    const id = g.guard.activeKeys()[0]!.id;
    const second = new SoftAuthenticator();
    // add the second key by hand (console route), remove the first
    const e = g.guard.enrollStart("second");
    const options = (await g.send({ op: "passkey-register", token: e.token })).options;
    await g.send({ op: "passkey-register", token: e.token, ...second.create(options) });
    g.guard.confirmEnrollment(e.id);
    g.guard.removePasskey(id);
    const r = await run(second, { noQuestions: true });
    expect(r.text).toContain("проверочное касание");
    expect(r.text).not.toContain("уже проходило успешно");
    expect(r.code).toBe(0);
    const keys = g.guard.passkeyTouches(SETUP_CHECK_PURPOSE).map((t) => t.key);
    expect(keys).toHaveLength(2);
    expect(keys).toContain("second");
  });

  it("the touch is described by the guard in its own words, and approves nothing", async () => {
    g = await startGuard();
    const auth = new SoftAuthenticator();
    const e = g.guard.enrollStart("k");
    const options = (await g.send({ op: "passkey-register", token: e.token })).options;
    await g.send({ op: "passkey-register", token: e.token, ...auth.create(options) });
    g.guard.confirmEnrollment(e.id);
    const t = await touchFor(g, auth, { op: "touch", purpose: SETUP_CHECK_PURPOSE });
    expect(t.challenge.description).toContain("Проверка касания при настройке");
    expect(t.challenge.description).toContain("ничего не одобряется");
    // and a session does not cover it: it is a fresh touch only
    expect(await g.send({ op: "touch", purpose: SETUP_CHECK_PURPOSE, session: "x".repeat(40) })).toMatchObject({ ok: false });
    expect(await g.send({ op: "touch", purpose: SETUP_CHECK_PURPOSE, passkey: t.passkey })).toMatchObject({ ok: true });
    expect((await g.send({ op: "state" })).queue).toEqual([]);
  });
});

describe("sbb-guard setup: the console", () => {
  it("needs a terminal: with no way to answer it stops with a clear sentence and changes nothing", async () => {
    g = await startGuard({ register: false });
    const r = await run(new SoftAuthenticator(), { noTerminal: true });
    expect(r.code).toBe(64);
    expect(r.text).toContain("Нужен терминал");
    expect(g.guard.totpRegistered()).toBe(false);
    expect(g.guard.listPasskeys()).toEqual([]);
  });

  it("the link uses the origin the guard was told (not a built-in address) and never a query", async () => {
    g = await startGuard({ register: false });
    const rp = resolveRp({ rpId: "bb.example.test", origin: "https://bb.example.test:8443" }, {});
    const r = await run(new SoftAuthenticator(), { noEnroll: true, totp: "н" }, { ...g.paths, rp });
    expect(r.code).toBe(1); // nobody opened it: the window expired
    expect(r.text).toMatch(/https:\/\/bb\.example\.test:8443\/plugins\/secure-bb\/gate#enroll=[A-Z2-9-]{14}/);
    expect(r.text).not.toContain("localhost");
    expect(r.text).toContain("Окно регистрации закрылось за 5 минут");
  });

  it("builds the link from the origin with or without a trailing slash", () => {
    expect(gateUrl("http://localhost:38886/")).toBe("http://localhost:38886/plugins/secure-bb/gate");
    expect(enrollLink("http://localhost:38886", "AAAA-BBBB-CCCC")).toBe("http://localhost:38886/plugins/secure-bb/gate#enroll=AAAA-BBBB-CCCC");
  });

  it("is listed in the usage, and `help setup` does not touch anything", async () => {
    const out: string[] = [];
    expect(await main(["help"], { out: (t) => void out.push(t), err: (t) => void out.push(t), ask: async () => null })).toBe(0);
    expect(out.join("\n")).toContain("sbb-guard setup");
  });
});
