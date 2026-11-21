// sbb-guard: serve | totp-register | totp-disable | passkey-enroll | passkey-list | passkey-remove | status | journal-verify | import
import { createHash } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import net from "node:net";
import { createInterface } from "node:readline/promises";
import { resolvePaths, type GuardPaths } from "./config.ts";
import { openDb, privateDir } from "./db.ts";
import { Guard, GuardError, type ImportItem, type PasskeyRow } from "./guard.ts";
import { encodeQr } from "./qr.ts";
import { listen } from "./server.ts";
import { generateSecret, otpauthUri } from "./totp.ts";

export const VERSION = "0.1.0";
const ALIVE_EVERY_MS = 5000;
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

  sbb-guard serve [--data DIR] [--socket PATH] [--socket-gid GID] [--rp-id ID] [--origin URL]
  sbb-guard totp-register [--data DIR] [--code CODE] [--replacing-code CODE]
  sbb-guard totp-disable [--data DIR] [--yes]
  sbb-guard passkey-enroll [--data DIR] [--label NAME] [--rp-id ID] [--origin URL]
  sbb-guard passkey-list [--data DIR]
  sbb-guard passkey-remove ID [--data DIR] [--yes]
  sbb-guard status [--data DIR] [--socket PATH]
  sbb-guard journal-verify [--data DIR]
  sbb-guard import FILE [--data DIR] [--yes] [--digest SHA256]

Paths: --data / SBB_GUARD_DATA (default /var/sbb-guard), --socket / SBB_GUARD_SOCKET (default <data>/run/guard.sock),
--socket-gid / SBB_GUARD_SOCKET_GID.
Passkeys: --rp-id / SBB_GUARD_RP_ID (default localhost) and --origin / SBB_GUARD_ORIGIN (default http://localhost:38886): the page must be opened
at exactly that origin (WebAuthn does not work on 127.0.0.1). A key is registered only here: passkey-enroll prints a one-time token, valid for 5 minutes.`;

type Opts = Record<string, string | boolean>;
export function parseArgs(argv: string[]): { cmd: string | undefined; positionals: string[]; opts: Opts } {
  const opts: Opts = {};
  const positionals: string[] = [];
  let cmd: string | undefined;
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a.startsWith("--")) {
      const key = a.slice(2);
      const eq = key.indexOf("=");
      if (eq >= 0) opts[key.slice(0, eq)] = key.slice(eq + 1);
      else if (key === "yes" || key === "help") opts[key] = true;
      else {
        const v = argv[i + 1];
        if (v === undefined || v.startsWith("--")) throw new Error(`--${key} needs a value`);
        opts[key] = v;
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
  return { guard: new Guard({ db, now, secretPath: paths.secret, headPath: paths.head, rp: paths.rp }), close: () => db.close() };
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
}

/**
 * Opens the registration window (5 minutes), prints the one-time token, waits for the page to register a key, shows what it registered
 * and asks for `y`. No flag skips the question: a key that a harmful plugin managed to register first must be seen by a person.
 */
export async function passkeyEnroll(paths: GuardPaths, io: Io, opts: Opts, now: () => number = Date.now, deps: EnrollDeps = {}): Promise<number> {
  const sleep = deps.sleep ?? ((ms: number) => new Promise<void>((r) => setTimeout(r, ms)));
  const { guard, close } = open(paths, now);
  try {
    const label = optStr(opts, "label") ?? `key-${new Date(now()).toISOString().slice(0, 16).replace(/[-:T]/g, "")}`;
    const e = guard.enrollStart(label);
    io.out(`Registration window is open until ${new Date(e.expiresAt).toISOString()} (5 minutes).`);
    io.out(`Key label:  ${e.label}`);
    io.out(`Token:      ${e.token}`);
    io.out(`Open ${paths.rp.origin} (exactly this address, not 127.0.0.1), the secure-bb page, "Добавить passkey", enter the token and touch the sensor.`);
    io.out("Waiting for the key…");
    for (;;) {
      const st = guard.enrollmentStatus(e.id);
      if (st.key) {
        io.out("");
        io.out(`A key was registered:  ${st.key.label}`);
        io.out(`  AAGUID:       ${st.key.aaguid}`);
        io.out(`  fingerprint:  ${groups(st.key.fingerprint)}`);
        io.out("If you did not just do this yourself, answer no: something else used the token.");
        const a = await io.ask("Activate this key? [y/N] ");
        if (!yes(a)) {
          guard.rejectEnrollment(e.id, a === null ? "no answer" : "declined");
          io.err("not confirmed; the key is discarded and the window is closed");
          return 1;
        }
        guard.confirmEnrollment(e.id);
        io.out(`Key ${st.key.label} is active.`);
        return 0;
      }
      if (st.state !== "open") {
        io.err(st.state === "expired" ? "the registration window expired; nothing was registered" : `the registration window is ${st.state}; nothing was registered (five wrong tokens close it)`);
        guard.rejectEnrollment(e.id, st.state);
        return 1;
      }
      await sleep(deps.pollMs ?? 500);
    }
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

export async function serve(paths: GuardPaths, io: Io, signal?: AbortSignal): Promise<number> {
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
    paths = resolvePaths({ data: optStr(opts, "data"), socket: optStr(opts, "socket"), socketGid: optStr(opts, "socket-gid"), rpId: optStr(opts, "rp-id"), origin: optStr(opts, "origin") });
  } catch (err) {
    io.err(err instanceof Error ? err.message : String(err));
    return 64;
  }
  try {
    switch (cmd) {
      case "serve":
        return await serve(paths, io);
      case "totp-register":
        return await totpRegister(paths, io, opts);
      case "totp-disable":
        return await totpDisable(paths, io, opts);
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

