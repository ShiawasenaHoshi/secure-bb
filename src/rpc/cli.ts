// The commands for agents (`bb secure-bb …`): status, propose, check, log and the rest. Terse by design: no reasons, no stage (spec §11).
import { join, resolve as resolvePath } from "node:path";
import { PluginCliError, cliCommand, defineCli } from "@get-bb/plugin-sdk";
import { Gate } from "../gate.js";
import { isThirdParty } from "../probe.js";
import { checkPathRefusal, checkSummary } from "../checkpath.js";
import { agentLine } from "../journal.js";
import { propose } from "../propose.js";
import { publishLine } from "../publish/view.js";
import { ScanError } from "../scan/scanner.js";
import { scanLine, scanView } from "../scan/view.js";
import { Sentinel } from "../sentinel/sentinel.js";
import { feedText } from "../sentinel/view.js";
import { formatWatch } from "../watch/format.js";
import type { RpcCtx } from "./guard-helpers.js";

export function registerCli(c: RpcCtx) {
  const { agents, aiScanner, bb, changed, dataDir, gate, guardLink, jev, journal, listPlugins, now, publisher, runChecks, safeDataDir, sentinel, sentinelStore, skillGuard, snapshotsRoot, state, store, taint, threads, verifyDeps, watch } = c;
  // ---- CLI for agents ------------------------------------------------------
  bb.cli.register(
    defineCli({
      name: "secure-bb",
      summary: "Gate for plugin code: install plugins only through `propose`",
      commands: {
        status: cliCommand({
          summary: "Is the gate on, and is a trust window open for this thread",
          options: {},
          async run(_input, ctx) {
            // Deliberately terse: no stage, no second-factor state, no reasons.
            const open = ctx.threadId
              ? (await Promise.all(gate.openWindows().map(async (w) => ((await gate.windowCovering(w.pluginId, ctx.threadId ?? null)) ? w : null)))).filter((w) => w !== null)
              : [];
            const lines = [
              `gate before load: ${state.hookRegistered ? "yes" : "no (after the fact)"}`,
              `trust window for this thread: ${open.length > 0 ? `open (${open.map((w) => `${w.pluginId}, ${Math.ceil((Math.min(w.expiresAt, w.hardExpiresAt) - now()) / 60_000)} min`).join("; ")})` : "closed"}`,
              agentLine(journal()),
              `repositories that do not taint a thread: ${store.trustedRepos().length}`,
            ];
            return { exitCode: 0, stdout: lines.join("\n") };
          },
        }),
        log: cliCommand({
          summary: "Recent gate decisions; --verify checks the integrity of the journal (hash chain)",
          options: {
            limit: { type: "integer", min: 1, max: 100, default: 20, description: "How many entries (1-100)" },
            verify: { type: "boolean", description: "Check the hash chain of the journal instead of listing it; exit code 2 when it is broken" },
          },
          async run(input) {
            if (input.options.verify) {
              const report = journal(true);
              if (!report.ok) changed();
              // For an agent: only whether it holds. Which record, and how, is for the human on the page.
              return { exitCode: report.ok ? 0 : 2, stdout: agentLine(report) };
            }
            // Whether an approval session is open is not for agents: its records stay on the page.
            const rows = store.listLog(input.options.limit, "session.");
            // No reasons here: agents read this too (spec §11). The page has them.
            const text = rows
              .map((r) => {
                const d = (r.detail && typeof r.detail === "object" ? r.detail : {}) as Record<string, unknown>;
                const parts = [new Date(r.ts).toISOString(), r.kind];
                if (r.pluginId) parts.push(d.version ? `${r.pluginId}@${String(d.version)}` : r.pluginId);
                if (d.review !== undefined) parts.push(`review #${String(d.review)}`);
                return parts.join(" ");
              })
              .join("\n");
            return { exitCode: 0, stdout: text || "(empty)" };
          },
        }),
        config: cliCommand({
          summary: "Config watchdog: differences from the approved configuration snapshot",
          options: {
            scan: { type: "boolean", description: "Check right now before printing" },
            limit: { type: "integer", min: 1, max: 100, default: 20, description: "How many entries (1-100)" },
          },
          async run(input) {
            if (input.options.scan) await watch.scan().then((r) => (r.found + r.accepted + r.rolledBack > 0 ? changed() : undefined));
            return { exitCode: 0, stdout: formatWatch(watch.view(), now(), input.options.limit) };
          },
        }),
        skills: cliCommand({
          summary: "Skills guard: which installed skills are pinned, which wait for a human or were removed (no reasons: they are for the person on the page)",
          options: {
            scan: { type: "boolean", description: "Check right now before printing" },
          },
          async run(input) {
            if (input.options.scan) await watch.scan().then((r) => (r.found + r.accepted > 0 ? changed() : undefined));
            const v = skillGuard.view();
            const lines = [
              `skills pinned: ${v.pinned.total} (${v.pinned.builtin} built-in, ${v.pinned.baseline} existing before the module, ${v.pinned.approved} approved)`,
              `waiting for a human: ${v.open.length}`,
              ...v.open.map((r) => `  #${r.id} ${r.name} (${r.scope}): ${r.state === "alarm" ? "alarm" : "held by secure-bb"}`),
            ];
            const removed = v.recent.filter((r) => r.state === "removed").slice(0, 5);
            if (removed.length > 0) lines.push("removed by secure-bb:", ...removed.map((r) => `  #${r.id} ${r.name} (${r.scope})`));
            return { exitCode: 0, stdout: lines.join("\n") };
          },
        }),
        scan: cliCommand({
          summary: "Optional AI scan: print the settings and the latest results, or start a scan of an installed third-party plugin (off unless a human turned it on)",
          positionals: [{ name: "plugin", description: "Plugin id to scan; omit to only print", required: false }],
          options: {},
          async run(input) {
            const ai = store.aiSettings();
            const lines: string[] = [`AI scan: ${ai.enabled ? "on" : "off"}${ai.enabled ? `; on freeze: ${ai.autoFreeze ? "yes" : "no"}; externals: ${ai.autoExternal ? "yes" : "no"}; second model: ${ai.second ? ai.secondModel : "no"}` : ""}`];
            const id = input.positionals.plugin;
            if (id) {
              if (!ai.enabled) throw new PluginCliError("AI scan is off; a human turns it on in the secure-bb page", { code: "scan_off" });
              const installed = (await listPlugins()).find((p) => p.id === id && isThirdParty(p));
              if (!installed) throw new PluginCliError(`no installed third-party plugin ${id}`, { code: "not_found" });
              try {
                const { row } = await aiScanner.start({ pluginId: installed.id, version: installed.version, dir: installed.rootDir, contentHash: null, trigger: "cli" });
                changed();
                lines.push(`scan #${row.id} of ${installed.id}@${installed.version}: ${row.status === "running" ? "started (takes a few minutes)" : row.status}`);
              } catch (err) {
                if (err instanceof ScanError) throw new PluginCliError(err.message, { code: "scan_failed" });
                throw err;
              }
            } else {
              const recent = store.listScans(5).map((r) => scanLine(scanView(r)));
              lines.push(...(recent.length > 0 ? recent : ["no scans yet"]));
            }
            return { exitCode: 0, stdout: lines.join("\n") };
          },
        }),
        publish: cliCommand({
          summary: "Publishing of frozen versions of our plugins to the plugins repository: state and latest results (settings and the token are for the person on the page)",
          options: { limit: { type: "integer", min: 1, max: 20, default: 5, description: "How many results (1-20)" } },
          async run(input) {
            const lines = [publishLine(store.publishSettings(), publisher.state()), ...store.listPublications(input.options.limit).map((r) => `${new Date(r.startedAt).toISOString()} ${r.pluginId}@${r.version} ${r.status}`)];
            return { exitCode: 0, stdout: lines.join("\n") };
          },
        }),
        check: cliCommand({
          summary: "Run the checks on a plugin directory without installing it; prints a summary only (details are for the page). Not for bb's own data or directories private to the server user",
          positionals: [{ name: "path", description: "Plugin directory on this machine", required: true }],
          options: {},
          async run(input, ctx) {
            const dir = resolvePath(ctx.cwd ?? process.cwd(), input.positionals.path);
            // Runs as the server's user: not for bb's own data or what is private to that user (threat model F9). The reason stays in the log.
            const refused = checkPathRefusal(dir, { dataDir: safeDataDir(), serverUid: typeof process.getuid === "function" ? process.getuid() : null });
            if (refused !== null) {
              store.log("check.refused", null, null, { reason: refused });
              throw new PluginCliError("this directory cannot be checked from here", { code: "check_refused" });
            }
            let result;
            try {
              result = await verifyDeps(await runChecks(dir));
            } catch (err) {
              throw new PluginCliError(`cannot check ${dir}: ${err instanceof Error ? err.message : String(err)}`, { code: "check_failed" });
            }
            return { exitCode: 0, stdout: checkSummary(result) };
          },
        }),
        watchman: cliCommand({
          summary: "Sentinel feed (observation only; it never answers approval cards): recent actions, categories that fired, what the human did with the card",
          options: { limit: { type: "integer", min: 1, max: 50, default: 10, description: "How many entries (1-50)" } },
          async run(input) {
            await sentinel.refreshOutcomes().catch(() => 0);
            const s = sentinel.settings();
            const head = `watchman: ${s.enabled ? `on (${s.allThreads ? "all threads" : "threads with an open trust window"}); observation only, cards are not answered` : "off"}${jev.keyConfigured() ? "" : "; solver key not set"}`;
            const rows = sentinelStore.list(input.options.limit);
            return { exitCode: 0, stdout: [head, ...(rows.length > 0 ? rows.map((r) => feedText(r, s.riskThreshold)) : ["(feed is empty)"])].join("\n") };
          },
        }),
        propose: cliCommand({
          summary: "Install or update a plugin through the gate (the only allowed way)",
          positionals: [{ name: "path", description: "Plugin directory on this machine", required: true }],
          options: {},
          async run(input, ctx) {
            const res = await propose(
              {
                gate,
                store,
                snapshotsRoot,
                invokerIsServerMachine: async (threadId) => {
                  if (!threadId) return true; // a human in a terminal: the CLI runs where they are
                  try {
                    const th = (await bb.sdk.threads.get({ threadId })) as unknown as { environmentId?: string | null };
                    if (!th.environmentId) return false;
                    const env = (await bb.sdk.environments.get({ environmentId: th.environmentId })) as unknown as { hostId?: string | null };
                    const cfg = (await bb.sdk.system.config()) as unknown as { primaryHostId?: string | null };
                    if (!env.hostId || !cfg.primaryHostId) return false;
                    return env.hostId === cfg.primaryHostId;
                  } catch {
                    // Fail closed: reading a path on the wrong machine is worse than refusing.
                    return false;
                  }
                },
                install: async (dir) => {
                  const p = await bb.sdk.plugins.install({ source: dir });
                  return { id: p.id, version: p.version, status: p.status, statusDetail: p.statusDetail };
                },
                afterInstall: (dir) => gate.recordBuilt(dir),
                changed,
                guarded: guardLink !== null,
              },
              { path: input.positionals.path, cwd: ctx.cwd, threadId: ctx.threadId ?? null },
            );
            if (res.exitCode === 1 && res.stderr && !res.stdout) throw new PluginCliError(res.stderr, { code: "propose_failed" });
            return res;
          },
        }),
      },
    }),
  );

}
