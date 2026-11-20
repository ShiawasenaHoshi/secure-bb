// Publishes the frozen version of one of OUR plugins to the plugins monorepo (spec §14).
//
//   <plugin-id>/ = a copy of the reviewed snapshot (no dist/, node_modules/, .git)
//   commit message   "<id>@<version> frozen <localHash>"      tag   "<id>-v<version>"
//
// What this guards: only snapshots made by `propose` (our own table, inside our snapshots directory) are ever
// published, and only after their bytes are hashed again. git runs without a shell, in a throwaway directory,
// with an empty HOME (no user gitconfig, no hooks) and without prompts. The token comes from a file named by
// an environment variable and reaches git only through the environment of the one child that talks to the
// network: never argv, never the address, never settings, never the database, never a log.
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { CommandSpec, ProcessRunner, RawRun } from "../scan/commands.js";
import type { ApprovalRow, ProposalRow, Store } from "../store.js";
import { hashTree, isInsideSnapshots, readPackageInfo } from "../tree.js";
import { copyForPublish, findSecrets } from "./files.js";
import { PUBLISH_TOKEN_FILE_ENV, type PublishRow, type PublishState, type PublishTrigger } from "./types.js";
import { SAFE_PLUGIN_ID, SAFE_VERSION } from "./validate.js";

const GIT_TIMEOUT_MS = 90_000;
const GIT_MAX_OUTPUT = 1024 * 1024;
const MAX_ATTEMPTS = 2;
/** Name of the variable the askpass script reads; it exists only in the environment of network git commands. */
const TOKEN_VAR = "SECURE_BB_PUBLISH_TOKEN";

export interface PublisherDeps {
  store: Store;
  now: () => number;
  /** Starts a process (no shell). Tests wrap the real one to see what git was given. */
  run: ProcessRunner;
  /** Value of `BB_SECURE_BB_PUBLISH_TOKEN_FILE`, or null. */
  tokenFile: string | null;
  snapshotsRoot: string;
  /** Environment of the server: only PATH is taken from it, to find `git`. */
  serverEnv?: NodeJS.ProcessEnv;
  /** Where throwaway directories go. Default: the system temp directory. */
  tmpRoot?: string;
  /** `file://` addresses are allowed in git's protocol list (tests). */
  allowFile?: boolean;
  gitBin?: string;
  log?: (message: string) => void;
  /** After every finished attempt (the page refreshes). */
  onDone?: (row: PublishRow) => void;
}

export interface PublishOutcome {
  /** Null: nothing was attempted (publishing is off). */
  row: PublishRow | null;
  note: string;
}

class Fail extends Error {}

export class Publisher {
  private chain: Promise<unknown> = Promise.resolve();

  constructor(private readonly d: PublisherDeps) {}

  /** Why it cannot run now, or "ready". */
  state(): PublishState {
    const s = this.d.store.publishSettings();
    if (!s.enabled) return "off";
    if (s.repoUrl === "") return "no-address";
    if (this.d.tokenFile === null) return "not-configured";
    return "ready";
  }

  /** A window froze (closed) and `pin` is the version that stays pinned. Never throws. */
  onFreeze(pluginId: string, pin: ApprovalRow | null): void {
    if (!this.d.store.publishSettings().enabled || !pin?.localHash) return;
    void this.publish({ pluginId, localHash: pin.localHash, trigger: "freeze" }).catch((e) => this.d.log?.(`publish failed: ${String(e)}`));
  }

  /** A human approved a proposal with a code (the "on approval" option). Never throws. */
  onApproved(proposalId: number | null): void {
    const s = this.d.store.publishSettings();
    if (!s.enabled || !s.onApprove || proposalId === null) return;
    const p = this.d.store.getProposal(proposalId);
    if (!p) return;
    void this.publish({ pluginId: p.pluginId, localHash: p.localHash, trigger: "approve" }).catch((e) => this.d.log?.(`publish failed: ${String(e)}`));
  }

  /** The pinned version of a plugin, on a human's request. */
  async publishPinned(pluginId: string): Promise<PublishOutcome> {
    const pin = this.d.store.latestApproval(pluginId);
    if (!pin?.localHash) return { row: null, note: "у плагина нет закреплённой версии из снимка secure-bb: публикуются только наши снимки" };
    return this.publish({ pluginId, localHash: pin.localHash, trigger: "manual" });
  }

  /** Resolves when everything started so far has finished (tests, shutdown). */
  async idle(): Promise<void> {
    await this.chain;
  }

  /** One at a time: two pushes of the same branch from here would only fight each other. */
  publish(t: { pluginId: string; localHash: string; trigger: PublishTrigger }): Promise<PublishOutcome> {
    const next = this.chain.then(() => this.run(t));
    this.chain = next.catch(() => undefined);
    return next;
  }

  private async run(t: { pluginId: string; localHash: string; trigger: PublishTrigger }): Promise<PublishOutcome> {
    const { store } = this.d;
    const settings = store.publishSettings();
    if (!settings.enabled) return { row: null, note: "публикация выключена" };
    const proposal = store.proposalByLocalHash(t.pluginId, t.localHash);
    // Foreign plugins: no snapshot of ours, no publication. This is also what keeps third-party code out of the repo.
    if (!proposal || !store.isApprovedSource(t.pluginId, t.localHash)) {
      const row = this.record(t, "—", settings, "skipped", "не наш плагин: нет одобренного снимка secure-bb (публикуются только снимки через propose)");
      return { row, note: row.detail! };
    }
    const row = store.insertPublication({ pluginId: t.pluginId, version: await this.versionOf(proposal), localHash: t.localHash, trigger: t.trigger, repoUrl: settings.repoUrl, branch: settings.branch });
    if (settings.repoUrl === "") return this.finish(row, "skipped", "адрес репозитория не задан");
    if (this.d.tokenFile === null) return this.finish(row, "skipped", `публикация не настроена: на сервере не задана переменная ${PUBLISH_TOKEN_FILE_ENV}`);
    const done = store.publishedTo(t.pluginId, t.localHash, settings.repoUrl, settings.branch);
    if (done) return this.finish(row, "unchanged", `уже опубликовано (запись #${done.id}${done.commit ? `, коммит ${done.commit.slice(0, 10)}` : ""})`, done.commit, done.tag);
    try {
      let last: Fail | null = null;
      for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
        try {
          const r = await this.attempt(row, proposal, settings.repoUrl, settings.branch);
          return this.finish(row, r.status, r.detail, r.commit, r.tag);
        } catch (err) {
          if (!(err instanceof Fail)) throw err;
          last = err;
          if (!/\[retry\]/.test(err.message)) break; // only a branch that moved is worth another go
        }
      }
      return this.finish(row, "failed", last!.message.replace("[retry] ", ""));
    } catch (err) {
      return this.finish(row, "failed", `неожиданная ошибка: ${this.scrub(err instanceof Error ? err.message : String(err), null)}`);
    }
  }

  private async versionOf(p: ProposalRow): Promise<string> {
    try {
      return (await readPackageInfo(p.snapshotDir)).version;
    } catch {
      return "?";
    }
  }

  private record(t: { pluginId: string; localHash: string; trigger: PublishTrigger }, version: string, s: { repoUrl: string; branch: string }, status: "skipped" | "failed", detail: string): PublishRow {
    const row = this.d.store.insertPublication({ pluginId: t.pluginId, version, localHash: t.localHash, trigger: t.trigger, repoUrl: s.repoUrl, branch: s.branch });
    return this.finish(row, status, detail).row!;
  }

  private finish(row: PublishRow, status: PublishRow["status"], detail: string, commit: string | null = null, tag: string | null = null): PublishOutcome {
    const { store } = this.d;
    store.finishPublication(row.id, { status, detail, commit, tag });
    const kind = status === "published" ? "publish.ok" : status === "unchanged" ? "publish.unchanged" : status === "skipped" ? "publish.skip" : "publish.fail";
    store.log(kind, row.pluginId, null, { version: row.version, local: row.localHash, trigger: row.trigger, tag, commit, detail: status === "published" ? undefined : detail });
    const fresh = store.getPublication(row.id)!;
    try {
      this.d.onDone?.(fresh);
    } catch {
      /* a refresh must never break a publication */
    }
    return { row: fresh, note: detail };
  }

  // ---- one attempt -------------------------------------------------------------------------------
  private async attempt(row: PublishRow, proposal: ProposalRow, repoUrl: string, branch: string): Promise<{ status: "published" | "unchanged"; commit: string; tag: string; detail: string }> {
    const dir = proposal.snapshotDir;
    if (!(await isInsideSnapshots(this.d.snapshotsRoot, dir))) throw new Fail("каталог снимка вне каталога снимков secure-bb");
    // Hash again: what is published is exactly what was reviewed.
    if ((await hashTree(dir)) !== proposal.localHash) throw new Fail("снимок изменился после проверки: хеш не совпал, публикация отменена");
    let info;
    try {
      info = await readPackageInfo(dir);
    } catch (err) {
      throw new Fail(`package.json снимка не читается: ${err instanceof Error ? err.message : String(err)}`);
    }
    if (info.id !== proposal.pluginId) throw new Fail("id плагина в снимке не совпадает с записью");
    if (info.id === "secure-bb") throw new Fail("secure-bb сам себя не публикует");
    if (!SAFE_PLUGIN_ID.test(info.id) || !SAFE_VERSION.test(info.version) || info.version.includes("..")) throw new Fail("id или версия плагина не годятся для имени каталога и тега");
    const token = await this.readToken();
    const found = await findSecrets(dir, [token]);
    if (found.length > 0) throw new Fail(`в снимке найдены секреты, публикация отменена: ${found.slice(0, 5).map((f) => `${f.rule} в ${f.file}`).join("; ")}`);

    const message = `${info.id}@${info.version} frozen ${proposal.localHash}`;
    const tag = `${info.id}-v${info.version}`;
    const work = await realpath(await mkdtemp(join(this.d.tmpRoot ?? tmpdir(), "sbb-publish-")));
    try {
      const home = join(work, "home");
      const repo = join(work, "repo");
      await mkdir(home, { recursive: true });
      await mkdir(repo);
      const askpass = join(work, "askpass.sh");
      await writeFile(askpass, `#!/bin/sh\ncase "$1" in\n  Username*) printf '%s\\n' x-access-token ;;\n  *) printf '%s\\n' "$${TOKEN_VAR}" ;;\nesac\n`, { mode: 0o700 });
      await chmod(askpass, 0o700);
      const git = (args: string[], o: { net?: boolean } = {}) => this.git(args, { cwd: repo, home, askpass, token: o.net ? token : null });

      await git(["init", "-q"]);
      await git(["symbolic-ref", "HEAD", `refs/heads/${branch}`]);
      await git(["remote", "add", "origin", repoUrl]);
      const remote = await git(["ls-remote", "origin", `refs/heads/${branch}`, `refs/tags/${tag}`], { net: true });
      const refs = new Map(remote.stdout.split("\n").filter(Boolean).map((l) => { const [sha, ref] = l.split("\t"); return [ref!, sha!] as const; }));

      if (refs.has(`refs/tags/${tag}`)) {
        // The version is already in the repository. Same source: done. Another source: never overwrite a tag.
        await git(["fetch", "-q", "--depth=1", "origin", `refs/tags/${tag}`], { net: true });
        const subject = (await git(["log", "-1", "--format=%s", "FETCH_HEAD"])).stdout.trim();
        if (subject === message) return { status: "unchanged", commit: refs.get(`refs/tags/${tag}`)!, tag, detail: `версия уже в репозитории (тег ${tag})` };
        throw new Fail(`тег ${tag} уже есть и указывает на другое содержимое (${subject.slice(0, 120)}); поднимите версию плагина, тег не перезаписывается`);
      }
      if (refs.has(`refs/heads/${branch}`)) {
        await git(["fetch", "-q", "--depth=1", "origin", `refs/heads/${branch}`], { net: true });
        await git(["checkout", "-q", "-B", branch, "FETCH_HEAD"]);
      }

      // The directory is the snapshot, no more: files the new version dropped must go too.
      await rm(join(repo, info.id), { recursive: true, force: true });
      await copyForPublish(dir, join(repo, info.id));
      // The source could have changed while it was being copied.
      if ((await hashTree(dir)) !== proposal.localHash) throw new Fail("снимок изменился во время копирования: публикация отменена");
      await git(["add", "-A", "--", info.id]);
      await git(["commit", "-q", "--no-verify", "--allow-empty", "-m", message]);
      await git(["tag", tag]);
      const commit = (await git(["rev-parse", "HEAD"])).stdout.trim();
      try {
        await git(["push", "-q", "--atomic", "origin", `HEAD:refs/heads/${branch}`, `refs/tags/${tag}`], { net: true });
      } catch (err) {
        const text = err instanceof Error ? err.message : String(err);
        if (/rejected|non-fast-forward|fetch first|stale info|cannot lock ref/i.test(text)) throw new Fail(`[retry] ветка ${branch} изменилась во время публикации: ${text}`);
        throw err;
      }
      return { status: "published", commit, tag, detail: `${info.id}@${info.version} → ${branch}, коммит ${commit.slice(0, 10)}, тег ${tag}` };
    } finally {
      await rm(work, { recursive: true, force: true });
    }
  }

  private async readToken(): Promise<string> {
    let text: string;
    try {
      text = await readFile(this.d.tokenFile!, "utf8");
    } catch {
      throw new Fail(`файл токена (${PUBLISH_TOKEN_FILE_ENV}) не читается`);
    }
    const token = text.trim();
    if (!/^[\x21-\x7e]{8,4096}$/.test(token)) throw new Fail(`в файле токена (${PUBLISH_TOKEN_FILE_ENV}) нет токена`);
    return token;
  }

  // ---- git ---------------------------------------------------------------------------------------
  /** The environment git runs in: nothing of the server's, nothing of the user's. */
  private gitEnv(o: { home: string; askpass: string; token: string | null }): Record<string, string> {
    const config: Array<[string, string]> = [
      ["core.hooksPath", "/dev/null"],
      ["core.fsmonitor", "false"],
      ["core.autocrlf", "false"],
      ["core.symlinks", "true"],
      ["credential.helper", ""],
      ["commit.gpgsign", "false"],
      ["tag.gpgsign", "false"],
      ["gc.auto", "0"],
      ["http.followRedirects", "false"],
      ["protocol.version", "2"],
    ];
    const env: Record<string, string> = {
      PATH: this.d.serverEnv?.PATH ?? process.env.PATH ?? "/usr/bin:/bin",
      HOME: o.home,
      XDG_CONFIG_HOME: join(o.home, ".config"),
      LANG: "C",
      LC_ALL: "C",
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_TERMINAL_PROMPT: "0",
      GIT_ASKPASS: o.askpass,
      GIT_ALLOW_PROTOCOL: this.d.allowFile === true ? "https:file" : "https",
      GIT_AUTHOR_NAME: "secure-bb",
      GIT_AUTHOR_EMAIL: "secure-bb@localhost",
      GIT_COMMITTER_NAME: "secure-bb",
      GIT_COMMITTER_EMAIL: "secure-bb@localhost",
      GIT_CONFIG_COUNT: String(config.length),
    };
    config.forEach(([k, v], i) => {
      env[`GIT_CONFIG_KEY_${i}`] = k;
      env[`GIT_CONFIG_VALUE_${i}`] = v;
    });
    if (o.token !== null) env[TOKEN_VAR] = o.token;
    return env;
  }

  private async git(args: string[], o: { cwd: string; home: string; askpass: string; token: string | null }): Promise<{ stdout: string }> {
    const spec: CommandSpec = { file: this.d.gitBin ?? "git", args, env: this.gitEnv(o), cwd: o.cwd, stdin: "", timeoutMs: GIT_TIMEOUT_MS, maxOutput: GIT_MAX_OUTPUT };
    const raw: RawRun = await this.d.run(spec);
    if (raw.kind === "spawn-failed") throw new Fail(raw.errno === "ENOENT" ? "git не найден на сервере" : `git не запустился: ${this.scrub(raw.message, o.token)}`);
    if (raw.kind === "timeout") throw new Fail(`git ${args[0]}: время вышло`);
    if (raw.code !== 0 || raw.truncated) throw new Fail(`git ${args[0]}: ${this.scrub(raw.stderr || raw.stdout || `код ${raw.code}`, o.token)}`);
    return { stdout: raw.stdout };
  }

  /** What may be shown: git's own words, minus the token and anything that looks like credentials in an address. */
  private scrub(text: string, token: string | null): string {
    let out = text;
    if (token) out = out.split(token).join("***");
    out = out.replace(/(https?:\/\/)[^\s/@]*@/g, "$1***@");
    return out.trim().slice(0, 600);
  }
}
