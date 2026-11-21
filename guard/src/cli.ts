// sbb-guard: serve | totp-register | totp-disable | passkey-enroll | passkey-list | passkey-remove | troubleshoot | status | journal-verify | import
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import net from "node:net";
import { dirname } from "node:path";
import { createInterface } from "node:readline/promises";
import { resolvePaths, type GuardPaths } from "./config.ts";
import { openDb, privateDir } from "./db.ts";
import { Guard, GuardError, SETUP_CHECK_PURPOSE, type ImportItem, type PasskeyRow } from "./guard.ts";
import { encodeQr } from "./qr.ts";
import { listen } from "./server.ts";
import { generateSecret, otpauthUri } from "./totp.ts";

export const VERSION = "0.1.0";
const ALIVE_EVERY_MS = 5000;
/** Agent watch: the period of the scan in `serve` (the design says every N minutes, 2 by default). */
export const AGENTS_SCAN_SEC = 120;
/** A start this long after the last mark of life is journaled as a gap (a crash, a stop, the machine was off). */
const GAP_MS = 30_000;

export interface Io {
  out: (text: string) => void;
  err: (text: string) => void;
  /** Reads one line from the person at the terminal; null when there is none. */
  ask: (question: string) => Promise<string | null>;
}
export const terminalIo: Io = {
  out: (t) => process.stdout.write(`${t}\n`),
  err: (t) => process.stderr.write(`${t}\n`),
  async ask(question) {
    if (!process.stdin.isTTY) return null;
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    try {
      return await rl.question(question);
    } finally {
      rl.close();
    }
  },
};

const USAGE = `sbb-guard ${VERSION} — decision guard for secure-bb

  sbb-guard serve [--data DIR] [--socket PATH] [--socket-gid GID] [--rp-id ID] [--origin URL] [--agents-home DIR] [--agents-root DIR]... [--agents-scan-sec N] [--restore-socket PATH]
                  [--plugins-root DIR]... [--known-source ENTRY]... [--offline]
  sbb-guard totp-register [--data DIR] [--code CODE] [--replacing-code CODE]
  sbb-guard totp-disable [--data DIR] [--yes]
  sbb-guard setup [--data DIR] [--label NAME] [--rp-id ID] [--origin URL]
  sbb-guard passkey-enroll [--data DIR] [--label NAME] [--rp-id ID] [--origin URL]
  sbb-guard passkey-list [--data DIR]
  sbb-guard passkey-remove ID [--data DIR] [--yes]
  sbb-guard troubleshoot MINUTES|off [--data DIR] [--code CODE]
  sbb-guard status [--data DIR] [--socket PATH]
  sbb-guard journal-verify [--data DIR]
  sbb-guard import FILE [--data DIR] [--yes] [--digest SHA256]

Agent watch (serve): --agents-home / SBB_GUARD_AGENTS_HOME (default /var/bbagent) is the agents' home; the working directories of threads are found in it
(data/plugins/*/host-data/workspaces/*). --agents-root DIR (repeatable) / SBB_GUARD_AGENTS_ROOTS (comma-separated) add more roots: the list is extended
from the console only. --agents-scan-sec (default 120) is the period of the scan. The guard's user needs read access to the home (the installer's ACL).
Putting a file back («Вернуть как было»): --restore-socket / SBB_GUARD_RESTORE_SOCKET (default /var/sbb-restore-run/restore.sock) is the socket of sbb-restore, the helper that runs
as the agents' user; the guard's user must be the only member of that socket's group. The guard itself never writes the agents' files.
Trust by source (serve): --plugins-root DIR (repeatable) / SBB_GUARD_PLUGINS_ROOTS: where the core keeps plugins installed from git; the guard reads a version
only from there (the guard's user needs read access: the installer's ACL), and without it nothing from git passes by itself. --known-source ENTRY (repeatable) /
SBB_GUARD_KNOWN_SOURCES: sources of the official catalog (github:owner/name or github:owner/*), the level "known". The owner's own sources are kept by the guard (a touch adds one).
Offline (serve): --offline / SBB_GUARD_OFFLINE=1: the checks make no network requests; node_modules is not compared with the npm registry and every package is scanned in full, as before registry verification existed.
Troubleshooting (console only, with a code): "troubleshoot 30" (or "30m") makes the guard pass everything for that long (at most 240 minutes), write every
decision into the journal and return by itself; the page shows a red bar with the time left. It is not an off switch: the guard has none. "troubleshoot off" ends it earlier.
Setup: a step-by-step wizard in Russian (a code from an app, a passkey with a link to the page, a test touch); run again, it does only what is missing.
Paths: --data / SBB_GUARD_DATA (default /var/sbb-guard), --socket / SBB_GUARD_SOCKET (default <data>/run/guard.sock),
--socket-gid / SBB_GUARD_SOCKET_GID.
Passkeys: --rp-id / SBB_GUARD_RP_ID (default localhost) and --origin / SBB_GUARD_ORIGIN (default http://localhost:38886): the page must be opened
at exactly that origin (WebAuthn does not work on 127.0.0.1). A key is registered only here: passkey-enroll prints a one-time token, valid for 5 minutes.`;

type Opts = Record<string, string | boolean>;
const REPEATABLE = new Set(["agents-root", "plugins-root", "known-source"]);
export function parseArgs(argv: string[]): { cmd: string | undefined; positionals: string[]; opts: Opts } {
  const opts: Opts = {};
  const positionals: string[] = [];
  let cmd: string | undefined;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a.startsWith("--")) {
      const key = a.slice(2);
      const eq = key.indexOf("=");
      if (eq >= 0) opts[key.slice(0, eq)] = REPEATABLE.has(key.slice(0, eq)) && typeof opts[key.slice(0, eq)] === "string" ? `${opts[key.slice(0, eq)] as string},${key.slice(eq + 1)}` : key.slice(eq + 1);
      else if (key === "yes" || key === "help" || key === "offline") opts[key] = true;
      else {
        const v = argv[i + 1];
        if (v === undefined || v.startsWith("--")) throw new Error(`--${key} needs a value`);
        // `--agents-root`, `--plugins-root` and `--known-source` may be given several times (joined with a comma).
        opts[key] = REPEATABLE.has(key) && typeof opts[key] === "string" ? `${opts[key] as string},${v}` : v;
        i++;
      }
    } else if (cmd === undefined) cmd = a;
    else positionals.push(a);
  }
  return { cmd, positionals, opts };
}

const optStr = (o: Opts, k: string): string | undefined => (typeof o[k] === "string" ? (o[k] as string) : undefined);

function open(paths: GuardPaths, now: () => number): { guard: Guard; close: () => void } {
  privateDir(paths.stateDir);
  const db = openDb(paths.db);
  return { guard: new Guard({ db, now, secretPath: paths.secret, headPath: paths.head, rp: paths.rp, trust: { pluginsRoots: paths.pluginsRoots, knownSources: paths.knownSources, offline: paths.offline }, agents: { home: paths.agentsHome, extraRoots: paths.agentsRoots, deny: [paths.dataDir, dirname(paths.socket), dirname(paths.restoreSocket)], restore: { socket: paths.restoreSocket } } }), close: () => db.close() };
}

/** One request to a running guard. */
export function request(socket: string, req: Record<string, unknown>, timeoutMs = 5000): Promise<Record<string, unknown>> {
  return new Promise((resolve, reject) => {
    const c = net.connect(socket);
    let buf = "";
    const timer = setTimeout(() => (c.destroy(), reject(new Error("timeout"))), timeoutMs);
    c.setEncoding("utf8");
    c.once("connect", () => c.write(`${JSON.stringify(req)}\n`));
    c.on("data", (d: string) => {
      buf += d;
      const nl = buf.indexOf("\n");
      if (nl >= 0) {
        clearTimeout(timer);
        c.destroy();
        try {
          resolve(JSON.parse(buf.slice(0, nl)) as Record<string, unknown>);
        } catch (e) {
          reject(e);
        }
      }
    });
    c.once("error", (e) => (clearTimeout(timer), reject(e)));
  });
}

export function renderQr(matrix: boolean[][]): string {
  // Two rows per text line with half blocks; a 4-module quiet zone so a phone can read it from a dark terminal.
  const q = 4;
  const n = matrix.length + 2 * q;
  const dark = (r: number, c: number): boolean => matrix[r - q]?.[c - q] === true;
  const lines: string[] = [];
  // The terminal is usually light-on-dark: draw "light" modules as filled blocks so the code reads as dark-on-light.
  for (let r = 0; r < n; r += 2) {
    let line = "";
    for (let c = 0; c < n; c++) {
      const top = !dark(r, c);
      const bottom = !dark(r + 1, c);
      line += top && bottom ? "█" : top ? "▀" : bottom ? "▄" : " ";
    }
    lines.push(line);
  }
  return lines.join("\n");
}

// ---- commands ---------------------------------------------------------------------------------------------
export async function totpRegister(paths: GuardPaths, io: Io, opts: Opts, now: () => number = Date.now): Promise<number> {
  const { guard, close } = open(paths, now);
  try {
    let replacing: string | undefined;
    if (guard.totpRegistered()) {
      io.out("A second factor is already registered. Replacing it needs a code of the current one (the secret is never shown again).");
      replacing = optStr(opts, "replacing-code") ?? (await io.ask("Code of the current authenticator: ")) ?? undefined;
      if (replacing === undefined) {
        io.err("no code given");
        return 1;
      }
    }
    const secret = generateSecret();
    const uri = otpauthUri(secret);
    io.out(renderQr(encodeQr(uri)));
    io.out("");
    io.out("Scan the QR code with an authenticator app (Aegis, 1Password, Google Authenticator…).");
    io.out(`If it cannot be scanned, enter this key by hand: ${secret}`);
    io.out("It is shown once, here, and is kept only in the guard's private directory. It never passes through bb.");
    const code = optStr(opts, "code") ?? (await io.ask("Enter the first code to confirm: ")) ?? undefined;
    if (code === undefined) {
      io.err("no code given; nothing was saved");
      return 1;
    }
    guard.registerSecret(secret, code.trim(), replacing === undefined ? {} : { replacingCode: replacing.trim() });
    io.out("Registered. The secret is locked and will not be shown again.");
    return 0;
  } catch (err) {
    if (err instanceof GuardError) {
      io.err(err.message);
      return 1;
    }
    throw err;
  } finally {
    close();
  }
}


// ---- passkeys and the switch for codes (console only) -----------------------------------------------------------------
const yes = (a: string | null): boolean => a !== null && /^y(es)?$/i.test(a.trim());
const groups = (hex: string): string => (hex.match(/.{1,4}/g) ?? []).join(" ");

export interface EnrollDeps {
  /** Waits between looks at the database; tests make it fast and move their clock. */
  sleep?: (ms: number) => Promise<void>;
  pollMs?: number;
  /** How long `setup` waits for the test touch (2 minutes by default). */
  checkTimeoutMs?: number;
}

/** What the console says while a key is being registered (`passkey-enroll` in English, `setup` in Russian for a person who is not an engineer). */
interface EnrollText {
  opened: (until: string) => void;
  announce: (e: { token: string; label: string }) => void;
  found: (k: PasskeyRow) => void;
  ask: string;
  yes: (a: string | null) => boolean;
  declined: (a: string | null) => string;
  confirmed: (label: string) => string;
  closed: (state: string) => string;
}
const ENROLL_EN = (io: Io, paths: GuardPaths): EnrollText => ({
  opened: (until) => io.out(`Registration window is open until ${until} (5 minutes).`),
  announce: (e) => {
    io.out(`Key label:  ${e.label}`);
    io.out(`Token:      ${e.token}`);
    io.out(`Open ${paths.rp.origin} (exactly this address, not 127.0.0.1), the secure-bb page, "Добавить passkey", enter the token and touch the sensor.`);
    io.out("Waiting for the key…");
  },
  found: (k) => {
    io.out("");
    io.out(`A key was registered:  ${k.label}`);
    io.out(`  AAGUID:       ${k.aaguid}`);
    io.out(`  fingerprint:  ${groups(k.fingerprint)}`);
    io.out("If you did not just do this yourself, answer no: something else used the token.");
  },
  ask: "Activate this key? [y/N] ",
  yes,
  declined: () => "not confirmed; the key is discarded and the window is closed",
  confirmed: (label) => `Key ${label} is active.`,
  closed: (state) => (state === "expired" ? "the registration window expired; nothing was registered" : `the registration window is ${state}; nothing was registered (five wrong tokens close it)`),
});

/**
 * Opens the registration window (5 minutes), tells the person the token, waits for the page to register a key, shows what it registered
 * and asks for `y`. No flag skips the question: a key that a harmful plugin managed to register first must be seen by a person.
 */
async function enrollWith(guard: Guard, io: Io, label: string, now: () => number, deps: EnrollDeps, text: EnrollText): Promise<number> {
  const sleep = deps.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const e = guard.enrollStart(label);
  text.opened(new Date(e.expiresAt).toISOString());
  text.announce(e);
  for (;;) {
    const st = guard.enrollmentStatus(e.id);
    if (st.key) {
      text.found(st.key);
      const a = await io.ask(text.ask);
      if (!text.yes(a)) {
        guard.rejectEnrollment(e.id, a === null ? "no answer" : "declined");
        io.err(text.declined(a));
        return 1;
      }
      guard.confirmEnrollment(e.id);
      io.out(text.confirmed(st.key.label));
      return 0;
    }
    if (st.state !== "open") {
      io.err(text.closed(st.state));
      guard.rejectEnrollment(e.id, st.state);
      return 1;
    }
    await sleep(deps.pollMs ?? 500);
  }
}

export async function passkeyEnroll(paths: GuardPaths, io: Io, opts: Opts, now: () => number = Date.now, deps: EnrollDeps = {}): Promise<number> {
  const { guard, close } = open(paths, now);
  try {
    return await enrollWith(guard, io, optStr(opts, "label") ?? defaultLabel(now), now, deps, ENROLL_EN(io, paths));
  } catch (err) {
    if (err instanceof GuardError) {
      io.err(err.message);
      return 1;
    }
    throw err;
  } finally {
    close();
  }
}
const defaultLabel = (now: () => number): string => `key-${new Date(now()).toISOString().slice(0, 16).replace(/[-:T]/g, "")}`;

// ---- setup: one command, step by step, in plain Russian ------------------------------------------------------------------
const yesRu = (a: string | null): boolean => a !== null && /^(y|yes|д|да)$/i.test(a.trim());
const noRu = (a: string | null): boolean => a !== null && /^(n|no|н|нет)$/i.test(a.trim());
/** Where the page lives: the origin the guard was told (WebAuthn works only there), then the plugin's path. */
export const GATE_PATH = "/plugins/secure-bb/gate";
export const gateUrl = (origin: string): string => `${origin.replace(/\/+$/, "")}${GATE_PATH}`;
/**
 * The link for adding a key: the token is in the fragment (#), which a browser never sends to a server; the page reads it and clears the
 * address bar at once. The token is also printed apart, in case the link cannot be opened where the page is.
 */
export const enrollLink = (origin: string, token: string): string => `${gateUrl(origin)}#enroll=${token}`;
export const SETUP_CHECK_WAIT_MS = 2 * 60_000;

/** Asks until the answer is "yes" or "no"; an empty answer is the default. null (no terminal) is reported as null. */
async function askYesNo(io: Io, question: string, dflt: boolean): Promise<boolean | null> {
  for (let i = 0; i < 3; i++) {
    const a = await io.ask(`${question} ${dflt ? "[Д/н]" : "[д/Н]"} `);
    if (a === null) return null;
    if (a.trim() === "") return dflt;
    if (yesRu(a)) return true;
    if (noRu(a)) return false;
    io.out("Ответьте «д» (да) или «н» (нет).");
  }
  return dflt;
}

/** Step: codes from an app. Returns true when the second factor now exists by this step. */
async function setupTotp(guard: Guard, io: Io, opts: Opts): Promise<"done" | "failed"> {
  const secret = generateSecret();
  io.out("");
  io.out(renderQr(encodeQr(otpauthUri(secret))));
  io.out("");
  io.out("Откройте на телефоне приложение для кодов (Aegis, 1Password, Google Authenticator, Яндекс Ключ…) и наведите камеру на этот квадрат.");
  io.out(`Если не получается считать, введите ключ вручную: ${secret}`);
  io.out("Ключ показан один раз, здесь. Он хранится только у сторожа и не проходит через bb.");
  for (let attempt = 1; attempt <= 3; attempt++) {
    const code = optStr(opts, "code") ?? (await io.ask("Введите шесть цифр из приложения, чтобы подтвердить: ")) ?? undefined;
    if (code === undefined) {
      io.err("Ответа нет, ничего не сохранено. Запустите `sbb-guard setup` снова.");
      return "failed";
    }
    try {
      guard.registerSecret(secret, code.trim());
      io.out("Готово: коды из приложения подключены. Секрет заперт и больше нигде не покажется.");
      return "done";
    } catch (err) {
      if (!(err instanceof GuardError)) throw err;
      io.err(`Код не подошёл (${attempt} из 3). Подождите, пока в приложении появится новый, и введите его.`);
      if (optStr(opts, "code") !== undefined) break;
    }
  }
  io.err("Не получилось подтвердить коды. Запустите `sbb-guard setup` снова: покажу новый QR.");
  return "failed";
}

/** Step: the test touch. Waits until the guard sees a good signature for the action `touch {purpose: "setup-check"}`. */
async function setupCheck(guard: Guard, io: Io, paths: GuardPaths, now: () => number, deps: EnrollDeps): Promise<boolean> {
  const sleep = deps.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const since = guard.lastJournalId();
  const until = now() + (deps.checkTimeoutMs ?? SETUP_CHECK_WAIT_MS);
  io.out("");
  io.out("Шаг: проверочное касание. Так мы убедимся, что ключ правда работает с этой страницей.");
  io.out(`  1. Откройте страницу: ${gateUrl(paths.rp.origin)}`);
  io.out("  2. Найдите блок «Passkey» и нажмите «Проверить касание».");
  io.out("  3. Приложите палец (или подтвердите так, как у вас принято). Ничего не одобряется и не меняется, это только проверка.");
  io.out("Жду до 2 минут…");
  for (;;) {
    const t = guard.passkeyTouches(SETUP_CHECK_PURPOSE, since)[0];
    if (t) {
      io.out(`Всё работает: касание принято (ключ «${t.key}»).`);
      return true;
    }
    if (now() >= until) {
      io.err("Касание не пришло за 2 минуты.");
      io.err("Чаще всего виноват менеджер паролей: его расширение в браузере перехватывает запрос. Посмотрите, нет ли его окна, и выберите ключ устройства (Touch ID / Windows Hello).");
      io.err("Страницу надо открывать ровно по адресу выше (localhost, не 127.0.0.1). Когда разберётесь, запустите `sbb-guard setup` ещё раз: пройдут только недостающие шаги.");
      return false;
    }
    await sleep(deps.pollMs ?? 500);
  }
}

function setupLeaflet(io: Io, paths: GuardPaths, guard: Guard): void {
  io.out("");
  io.out("Памятка");
  io.out(`  • Страница secure-bb: ${gateUrl(paths.rp.origin)} (открывайте именно по этому адресу).`);
  io.out("  • Одобряете вы: касанием пальца, а если ключ не под рукой — кодом из приложения (если он подключён).");
  io.out("  • Касание не срабатывает или «ничего не происходит»: чаще всего запрос перехватил менеджер паролей (расширение в браузере). Выберите в его окне ключ устройства или временно выключите расширение для этой страницы.");
  io.out(guard.totpRegistered() ? "  • Коды из приложения можно выключить позже: `sbb-guard totp-disable` (нужен хотя бы один рабочий ключ). Включить снова: `sbb-guard totp-register`." : "  • Коды из приложения сейчас не подключены; добавить их можно командой `sbb-guard totp-register`.");
  io.out("  • Список и удаление ключей: `sbb-guard passkey-list`, `sbb-guard passkey-remove НОМЕР`. Всё ли в порядке: `sbb-guard status`.");
}

/**
 * `sbb-guard setup`: the whole registration in one command. Every step looks at what already exists, so a second run does only what is missing and
 * breaks nothing (it never replaces a secret, never removes a key). The key is still activated only by `y` here, on the console.
 */
export async function setup(paths: GuardPaths, io: Io, opts: Opts, now: () => number = Date.now, deps: EnrollDeps = {}): Promise<number> {
  const { guard, close } = open(paths, now);
  try {
    const hadTotp = guard.totpRegistered();
    let hasKey = guard.activeKeys().length > 0;
    io.out("Настройка защиты secure-bb. Я задам несколько вопросов; каждый шаг можно пройти позже, запустив эту команду снова.");
    if (hadTotp || hasKey) {
      io.out(`Уже есть: ${[hadTotp ? "коды из приложения" : "", hasKey ? `ключи (${guard.activeKeys().length})` : ""].filter(Boolean).join(", ")}. Эти шаги пропускаю.`);
    }

    // Step 1: a second factor at all. Codes from an app, or (skip it) a passkey alone.
    let skippedTotp = false;
    if (!hadTotp && !hasKey && !guard.totpDisabled()) {
      io.out("");
      io.out("Шаг 1. Коды из приложения. Это запасной способ подтверждать решения, если ключ (касание пальцем) не под рукой.");
      const want = await askYesNo(io, "Подключить коды из приложения?", true);
      if (want === null) {
        io.err("Нужен терминал: мастер задаёт вопросы. Запустите `sbb-guard setup` в обычном окне терминала.");
        return 64;
      }
      if (want) {
        if ((await setupTotp(guard, io, opts)) === "failed") return 1;
      } else {
        skippedTotp = true;
        io.out("Хорошо, без кодов: подтверждать будет только ключ. Это надёжнее, но ключ придётся добавить сейчас.");
      }
    }

    // Step 2: a passkey.
    if (!hasKey) {
      const haveOther = guard.totpRegistered();
      io.out("");
      io.out("Шаг 2. Ключ passkey: подтверждение касанием пальца (Touch ID и подобное). Подпись нельзя перехватить в bb, поэтому это самый надёжный способ.");
      let go: boolean | null = true;
      if (haveOther && !skippedTotp) go = await askYesNo(io, "Добавить ключ сейчас?", true);
      if (go === null) {
        io.err("Нужен терминал: мастер задаёт вопросы.");
        return 64;
      }
      if (!go) io.out("Пропускаю ключ. Добавить его позже можно, запустив `sbb-guard setup` снова.");
      else {
        const label = optStr(opts, "label") ?? defaultLabel(now);
        const ru: EnrollText = {
          opened: (until) => io.out(`Окно регистрации открыто на 5 минут (до ${until}).`),
          announce: (e) => {
            io.out("Откройте эту ссылку в браузере на этом компьютере и нажмите «Добавить passkey», затем приложите палец:");
            io.out("");
            io.out(`  ${enrollLink(paths.rp.origin, e.token)}`);
            io.out("");
            io.out("Токен уже вписан в ссылку и пропадёт из адресной строки сразу после открытия. Если ссылка не открывается, откройте страницу сами и введите токен вручную:");
            io.out(`  страница: ${gateUrl(paths.rp.origin)}`);
            io.out(`  токен:    ${e.token}`);
            io.out(`Метка ключа: ${e.label}. Жду ключ…`);
          },
          found: (k) => {
            io.out("");
            io.out(`Зарегистрирован ключ «${k.label}».`);
            io.out(`  AAGUID:     ${k.aaguid}`);
            io.out(`  отпечаток:  ${groups(k.fingerprint)}`);
            io.out("Если вы сейчас сами этого не делали, ответьте «н»: значит, токеном воспользовался кто-то другой.");
          },
          ask: "Это ваш ключ, включить его? Введите y (да) или n (нет): ",
          yes: yesRu,
          declined: () => "Ключ не подтверждён: он удалён, окно регистрации закрыто. Запустите `sbb-guard setup` снова, когда будете готовы.",
          confirmed: (l) => `Ключ «${l}» включён.`,
          closed: (st) => (st === "expired" ? "Окно регистрации закрылось за 5 минут, ничего не зарегистрировано. Запустите `sbb-guard setup` снова." : `Окно регистрации стало «${st}», ничего не зарегистрировано (пять неверных токенов закрывают окно). Запустите \`sbb-guard setup\` снова.`),
        };
        if ((await enrollWith(guard, io, label, now, deps, ru)) !== 0) return 1;
        hasKey = true;
      }
    }

    // Step 3: the test touch — only when there is a key that has not passed it yet.
    let ok = true;
    const keys = guard.activeKeys();
    if (keys.length > 0) {
      const passed = new Set(guard.passkeyTouches(SETUP_CHECK_PURPOSE).map((t) => t.key));
      if (keys.every((k) => passed.has(k.label))) io.out("Проверочное касание уже проходило успешно: этот шаг пропускаю.");
      else ok = await setupCheck(guard, io, paths, now, deps);
    }
    if (!guard.totpRegistered() && guard.activeKeys().length === 0) {
      io.err("Ни кодов, ни ключа: подтверждать решения пока нечем. Запустите `sbb-guard setup` снова.");
      return 1;
    }
    setupLeaflet(io, paths, guard);
    return ok ? 0 : 1;
  } catch (err) {
    if (err instanceof GuardError) {
      io.err(err.message);
      return 1;
    }
    throw err;
  } finally {
    close();
  }
}

const stateText = (k: PasskeyRow): string => (k.state === "pending" ? "waiting for confirmation" : k.state);
export function passkeyList(paths: GuardPaths, io: Io, now: () => number = Date.now): number {
  if (!existsSync(paths.db)) {
    io.err("no database here");
    return 1;
  }
  const { guard, close } = open(paths, now);
  try {
    const keys = guard.listPasskeys();
    if (keys.length === 0) io.out("no passkeys");
    for (const k of keys) {
      io.out(`#${k.id}  ${k.label}  ${stateText(k)}  created ${new Date(k.createdAt).toISOString()}  ${k.lastUsedAt === null ? "never used" : `last used ${new Date(k.lastUsedAt).toISOString()}`}`);
      io.out(`     AAGUID ${k.aaguid}  fingerprint ${groups(k.fingerprint)}`);
    }
    io.out(`codes (TOTP): ${guard.totpDisabled() ? "switched off" : guard.totpRegistered() ? "registered" : "not registered"}`);
    return 0;
  } finally {
    close();
  }
}

export async function passkeyRemove(paths: GuardPaths, io: Io, idText: string, opts: Opts, now: () => number = Date.now): Promise<number> {
  const id = Number(idText.replace(/^#/, ""));
  if (!Number.isInteger(id) || id < 1) {
    io.err("passkey-remove needs the key number from `passkey-list`");
    return 64;
  }
  const { guard, close } = open(paths, now);
  try {
    if (opts.yes !== true && !yes(await io.ask(`Remove key #${id}? [y/N] `))) {
      io.err("not confirmed; nothing removed (use --yes to skip the question)");
      return 1;
    }
    const k = guard.removePasskey(id);
    io.out(`removed key #${k.id} (${k.label})`);
    return 0;
  } catch (err) {
    if (err instanceof GuardError) {
      io.err(err.message);
      return 1;
    }
    throw err;
  } finally {
    close();
  }
}

export async function totpDisable(paths: GuardPaths, io: Io, opts: Opts, now: () => number = Date.now): Promise<number> {
  const { guard, close } = open(paths, now);
  try {
    if (opts.yes !== true && !yes(await io.ask("Switch codes (TOTP) off? The secret is deleted; touches then need a passkey. [y/N] "))) {
      io.err("not confirmed; nothing changed (use --yes to skip the question)");
      return 1;
    }
    guard.totpDisable();
    io.out("Codes are off. `sbb-guard totp-register` switches them on again with a new secret.");
    return 0;
  } catch (err) {
    if (err instanceof GuardError) {
      io.err(err.message);
      return 1;
    }
    throw err;
  } finally {
    close();
  }
}

/** `troubleshoot 30m`: the guard passes everything for a while and writes it all down. Needs the console and a code (a passkey cannot be given at a terminal). */
export async function troubleshoot(paths: GuardPaths, io: Io, arg: string, opts: Opts, now: () => number = Date.now): Promise<number> {
  const { guard, close } = open(paths, now);
  try {
    if (arg === "off") {
      io.out(guard.troubleshootStop() ? "Troubleshooting mode is over: the guard decides as usual." : "Troubleshooting mode was not on.");
      return 0;
    }
    const m = /^(\d{1,4})\s*m?$/i.exec(arg.trim());
    if (m === null) {
      io.err("troubleshoot needs minutes (for example `troubleshoot 30` or `30m`), or `off`");
      return 64;
    }
    if (!guard.totpRegistered()) {
      io.err("troubleshooting mode needs a code, and no TOTP secret is registered here (`sbb-guard totp-register`)");
      return 1;
    }
    io.out(`For ${m[1]} min the guard will let EVERY plugin load, and write each decision into the journal. Then it returns by itself.`);
    const code = optStr(opts, "code") ?? (await io.ask("Code of the authenticator: ")) ?? undefined;
    if (code === undefined) {
      io.err("no code given; nothing changed");
      return 1;
    }
    const r = guard.troubleshootStart(Number(m[1]), code.trim());
    io.out(`Troubleshooting mode until ${new Date(r.until).toISOString()}. \`sbb-guard troubleshoot off\` ends it earlier.`);
    return 0;
  } catch (err) {
    if (err instanceof GuardError) {
      io.err(err.message);
      return 1;
    }
    throw err;
  } finally {
    close();
  }
}

export async function status(paths: GuardPaths, io: Io, now: () => number = Date.now): Promise<number> {
  io.out(`data:    ${paths.dataDir}`);
  io.out(`socket:  ${paths.socket}`);
  let live: Record<string, unknown> | null = null;
  try {
    live = await request(paths.socket, { op: "ping" }, 2000);
  } catch {
    live = null;
  }
  io.out(`daemon:  ${live && live.ok === true ? `running (protocol ${String(live.protocol)}, version ${String(live.version)})` : "not answering"}`);
  if (!existsSync(paths.db)) {
    io.out("database: none yet (the guard has never been started here)");
    return live ? 0 : 1;
  }
  const { guard, close } = open(paths, now);
  try {
    const s = guard.state() as {
      totp: { registered: boolean; blockedUntil: number };
      queue: Array<{ status: string }>;
      approvals: unknown[];
      windows: Array<{ pluginId: string; remainingSec: number }>;
    };
    io.out(`second factor: ${s.totp.registered ? "registered" : "NOT registered (run `sbb-guard totp-register`)"}${s.totp.blockedUntil > 0 ? `; approvals blocked until ${new Date(s.totp.blockedUntil).toISOString()}` : ""}`);
    {
      const t = guard.troubleshootUntil();
      if (t > 0) io.out(`TROUBLESHOOTING MODE: the guard passes everything until ${new Date(t).toISOString()} (every decision is in the journal)`);
    }
    io.out(`passkeys: ${guard.listPasskeys().filter((k) => k.state === "active").length} active (rp ${paths.rp.rpId}, origin ${paths.rp.origin}); codes: ${guard.totpDisabled() ? "switched off" : guard.totpRegistered() ? "on" : "not registered"}`);
    io.out(`held: ${s.queue.filter((q) => q.status === "held").length}; approved versions: ${s.approvals.length}; open windows: ${s.windows.length}${s.windows.map((w) => ` [${w.pluginId}, ${Math.ceil(w.remainingSec / 60)} min]`).join("")}`);
    const j = guard.verifyJournal();
    io.out(`journal: ${j.ok ? `ok (${j.entries} records, head ${j.head ? j.head.hash.slice(0, 12) : "-"})` : `BROKEN (${j.problems.length} problem(s)); run \`sbb-guard journal-verify\``}`);
    try {
      const mark = JSON.parse(readFileSync(paths.alive, "utf8")) as { ts: number; pid: number };
      io.out(`mark of life: ${Math.round((now() - mark.ts) / 1000)} s ago (pid ${mark.pid})`);
    } catch {
      io.out("mark of life: none");
    }
    return live && j.ok ? 0 : 1;
  } finally {
    close();
  }
}

export function journalVerify(paths: GuardPaths, io: Io, now: () => number = Date.now): number {
  if (!existsSync(paths.db)) {
    io.err("no database here");
    return 1;
  }
  const { guard, close } = open(paths, now);
  try {
    const r = guard.verifyJournal();
    if (r.ok) {
      io.out(`journal ok: ${r.entries} records, head #${r.head?.id ?? 0} ${r.head?.hash ?? "-"}`);
      return 0;
    }
    io.out(`journal BROKEN: ${r.problems.length} problem(s)`);
    for (const p of r.problems) io.out(`  ${p.kind}${p.id === null ? "" : ` #${p.id}`}: ${p.detail}`);
    return 2;
  } finally {
    close();
  }
}

/** What the plugin exports (`approvals-export`): format, then the approvals it believes are active. */
export const EXPORT_FORMAT = "secure-bb-approvals/1";

export function parseExport(text: string): ImportItem[] {
  const j = JSON.parse(text) as { format?: unknown; approvals?: unknown };
  if (j.format !== EXPORT_FORMAT || !Array.isArray(j.approvals)) throw new Error(`not an export of ${EXPORT_FORMAT}`);
  if (j.approvals.length > 5000) throw new Error("too many approvals in one file");
  return j.approvals.map((a, i) => {
    const o = a as Record<string, unknown>;
    try {
      const s = (v: unknown, max: number) => {
        if (typeof v !== "string" || v.length === 0 || v.length > max) throw new Error("bad string");
        return v;
      };
      const opt = (v: unknown) => (v === null || v === undefined ? null : s(v, 512));
      if (typeof o.approvedAt !== "number") throw new Error("bad time");
      return {
        contentHash: s(o.contentHash, 256),
        pluginId: s(o.pluginId, 128),
        version: s(o.version, 128),
        source: s(o.source, 2048),
        sourceKind: s(o.sourceKind, 64),
        gitCommit: opt(o.gitCommit),
        npmIntegrity: opt(o.npmIntegrity),
        approvedAt: o.approvedAt,
      };
    } catch {
      throw new Error(`approval #${i + 1} in the file is malformed`);
    }
  });
}

export async function importCmd(paths: GuardPaths, io: Io, file: string, opts: Opts, now: () => number = Date.now): Promise<number> {
  const text = readFileSync(file, "utf8");
  const digest = createHash("sha256").update(text).digest("hex");
  let items: ImportItem[];
  try {
    items = parseExport(text);
  } catch (err) {
    io.err(err instanceof Error ? err.message : String(err));
    return 1;
  }
  // The file was written by the plugin, i.e. by code inside bb: what it says is a claim, not a fact. The person at the console reads it first.
  io.out(`${file}: ${items.length} approval(s), sha256 ${digest}`);
  for (const i of items) io.out(`  ${i.pluginId}@${i.version}  ${i.contentHash.slice(0, 16)}…  ${i.sourceKind}: ${i.source}`);
  const want = optStr(opts, "digest");
  if (want !== undefined && want.toLowerCase() !== digest) {
    io.err("the file does not match --digest: it was changed after it was exported; nothing imported");
    return 1;
  }
  if (opts.yes !== true) {
    const a = await io.ask("Import these as approved versions? [y/N] ");
    if (a === null || !/^y(es)?$/i.test(a.trim())) {
      io.err("not confirmed; nothing imported (use --yes to skip the question)");
      return 1;
    }
  }
  const { guard, close } = open(paths, now);
  try {
    const r = guard.importApprovals(items, digest);
    io.out(`imported ${r.added}, already approved ${r.skipped}`);
    return 0;
  } finally {
    close();
  }
}

export async function serve(paths: GuardPaths, io: Io, signal?: AbortSignal, o: { scanSec?: number } = {}): Promise<number> {
  process.umask(0o077);
  const { guard, close } = open(paths, Date.now);
  const markAlive = (): void => {
    try {
      writeFileSync(paths.alive, JSON.stringify({ ts: Date.now(), pid: process.pid }), { mode: 0o600 });
    } catch {
      /* the mark is a convenience; failing to write it must not stop the guard */
    }
  };
  let previous: { ts: number } | null = null;
  try {
    previous = JSON.parse(readFileSync(paths.alive, "utf8")) as { ts: number };
  } catch {
    previous = null;
  }
  const report = guard.verifyJournal();
  guard.record(report.ok ? "start" : "start.journal-broken", null, null, {
    pid: process.pid,
    version: VERSION,
    gapSec: previous ? Math.round((Date.now() - previous.ts) / 1000) : null,
    unexpectedGap: previous ? Date.now() - previous.ts > GAP_MS : false,
    ...(report.ok ? {} : { problems: report.problems.slice(0, 10).map((p) => ({ kind: p.kind, id: p.id })) }),
  });
  if (!report.ok) io.err(`WARNING: the journal chain is broken (${report.problems.length} problem(s)); run \`sbb-guard journal-verify\``);
  const server = await listen({ guard, socket: paths.socket, socketGid: paths.socketGid, version: VERSION });
  markAlive();
  const timers = [setInterval(markAlive, ALIVE_EVERY_MS), setInterval(() => void guard.sweep(), 15_000)];
  // Agent watch: a scan at start and then every `scanSec` seconds. A failure of a scan is reported and the next one tries again; it never stops the guard.
  const scanAgents = (): void => {
    try {
      guard.agentsScan({ force: true });
    } catch (err) {
      process.stderr.write(`sbb-guard: agent watch scan failed: ${err instanceof Error ? err.message : String(err)}\n`);
    }
  };
  if (guard.agentsEnabled()) {
    scanAgents();
    const sec = Number.isFinite(o.scanSec) && (o.scanSec as number) >= 5 ? (o.scanSec as number) : AGENTS_SCAN_SEC;
    timers.push(setInterval(scanAgents, sec * 1000));
  }
  io.out(`sbb-guard ${VERSION} listening on ${paths.socket}${guard.totpRegistered() ? "" : " (no second factor yet: run `sbb-guard totp-register`)"}`);
  await new Promise<void>((resolve) => {
    const stop = (): void => resolve();
    process.once("SIGTERM", stop);
    process.once("SIGINT", stop);
    signal?.addEventListener("abort", stop, { once: true });
  });
  for (const t of timers) clearInterval(t);
  server.close();
  guard.record("stop", null, null, { pid: process.pid });
  close();
  return 0;
}

export async function main(argv: string[], io: Io = terminalIo): Promise<number> {
  let parsed: ReturnType<typeof parseArgs>;
  try {
    parsed = parseArgs(argv);
  } catch (err) {
    io.err(err instanceof Error ? err.message : String(err));
    return 64;
  }
  const { cmd, positionals, opts } = parsed;
  if (cmd === undefined || cmd === "help" || opts.help === true) {
    io.out(USAGE);
    return cmd === undefined ? 64 : 0;
  }
  let paths: GuardPaths;
  try {
    paths = resolvePaths({ data: optStr(opts, "data"), socket: optStr(opts, "socket"), socketGid: optStr(opts, "socket-gid"), rpId: optStr(opts, "rp-id"), origin: optStr(opts, "origin"), agentsHome: optStr(opts, "agents-home"), agentsRoots: optStr(opts, "agents-root"), restoreSocket: optStr(opts, "restore-socket"), pluginsRoots: optStr(opts, "plugins-root"), knownSources: optStr(opts, "known-source"), offline: opts.offline === true });
  } catch (err) {
    io.err(err instanceof Error ? err.message : String(err));
    return 64;
  }
  try {
    switch (cmd) {
      case "serve":
        return await serve(paths, io, undefined, { scanSec: Number(optStr(opts, "agents-scan-sec") ?? AGENTS_SCAN_SEC) });
      case "totp-register":
        return await totpRegister(paths, io, opts);
      case "totp-disable":
        return await totpDisable(paths, io, opts);
      case "setup":
        return await setup(paths, io, opts);
      case "passkey-enroll":
        return await passkeyEnroll(paths, io, opts);
      case "passkey-list":
        return passkeyList(paths, io);
      case "passkey-remove":
        if (positionals.length !== 1) {
          io.err("passkey-remove needs one key number");
          return 64;
        }
        return await passkeyRemove(paths, io, positionals[0]!, opts);
      case "troubleshoot":
        if (positionals.length !== 1) {
          io.err("troubleshoot needs minutes (`troubleshoot 30`) or `off`");
          return 64;
        }
        return await troubleshoot(paths, io, positionals[0]!, opts);
      case "status":
        return await status(paths, io);
      case "journal-verify":
        return journalVerify(paths, io);
      case "import":
        if (positionals.length !== 1) {
          io.err("import needs one file");
          return 64;
        }
        return await importCmd(paths, io, positionals[0]!, opts);
      default:
        io.err(`unknown command: ${cmd}\n${USAGE}`);
        return 64;
    }
  } catch (err) {
    io.err(`sbb-guard: ${err instanceof Error ? err.message : String(err)}`);
    return 1;
  }
}

