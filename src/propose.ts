// `bb secure-bb propose <path>`: the only way agents install plugins.
// The plugin directory is copied into secure-bb's own snapshots directory and
// installed from there, so what was reviewed is exactly what gets loaded.
import { mkdir, realpath, stat } from "node:fs/promises";
import { join, resolve } from "node:path";
import { BLOCKED_REASON, bySeverity, summarize } from "./decision.js";
import type { Gate } from "./gate.js";
import type { Store } from "./store.js";
import { T } from "./text.js";
import { copyTree, findEscapingSymlinks, hashTree, readPackageInfo, removeTree } from "./tree.js";

export interface ProposeDeps {
  gate: Gate;
  store: Store;
  snapshotsRoot: string;
  /** False when the invoking thread runs on another machine (its paths are not ours). */
  invokerIsServerMachine: (threadId: string | null) => Promise<boolean>;
  install: (dir: string) => Promise<{ id: string; version: string; status: string; statusDetail: string | null }>;
  /** Called after a successful install: lets the gate record what bb built. */
  afterInstall?: (dir: string) => Promise<void>;
  changed: () => void;
  /**
   * Guard mode: whether to install is not decided here. The guard holds what no human approved and no window covers,
   * and its queue entry (made when the core asks) is what the human sees; a snapshot that never reached the core would have none.
   */
  guarded?: boolean;
}

/**
 * What an agent may be told about a plugin's status: never a rule name, a path or a reason (they would
 * let it probe for a bypass). Anything of ours is reduced to "held/rejected by secure-bb: review #N".
 * Null: the status detail is not ours.
 */
export function agentStatusDetail(detail: string | null): string | null {
  if (detail === null || !/secure-bb/.test(detail)) return null;
  const review = /review #(\d+)/.exec(detail);
  if (/rejected/i.test(detail)) return review ? T.agentRejected(Number(review[1])) : "rejected by secure-bb";
  return review ? T.agentHeld(Number(review[1])) : T.agentHeldNoReview;
}

export interface CliResult {
  exitCode: number;
  stdout?: string;
  stderr?: string;
}

export async function propose(
  d: ProposeDeps,
  args: { path: string; cwd: string | undefined; threadId: string | null },
): Promise<CliResult> {
  if (!(await d.invokerIsServerMachine(args.threadId))) {
    return { exitCode: 1, stderr: "propose reads the plugin from the bb server's disk; this thread runs on another machine. Copy the plugin to the server machine first." };
  }
  const abs = resolve(args.cwd ?? process.cwd(), args.path);
  try {
    if (!(await stat(abs)).isDirectory()) throw new Error("not a directory");
  } catch {
    return { exitCode: 1, stderr: `not a plugin directory: ${args.path}` };
  }

  let info;
  try {
    info = await readPackageInfo(abs);
  } catch (err) {
    return { exitCode: 1, stderr: err instanceof Error ? err.message : String(err) };
  }
  if (info.id === "secure-bb") return { exitCode: 1, stderr: "secure-bb cannot be proposed through itself; a human updates it." };
  if (!info.hasServer) return { exitCode: 1, stderr: `${info.id}: package.json has no bb.server entry` };

  const escaping = await findEscapingSymlinks(abs);
  if (escaping.length > 0)
    return {
      exitCode: 1,
      stderr: `${info.id}: symlinks that point outside the plugin directory are not allowed (${escaping.slice(0, 5).join(", ")}${escaping.length > 5 ? ", …" : ""})`,
    };

  const localHash = await hashTree(abs);
  await mkdir(join(d.snapshotsRoot, info.id), { recursive: true });
  const target = join(await realpath(join(d.snapshotsRoot, info.id)), localHash);
  let exists = false;
  try {
    exists = (await stat(target)).isDirectory();
  } catch {
    exists = false;
  }
  // A snapshot directory is only reused if its bytes still match its name: an
  // interrupted copy or a tampered directory is replaced, never trusted.
  if (exists && (await hashTree(target)) !== localHash) {
    await removeTree(target);
    exists = false;
  }
  if (!exists) {
    await copyTree(abs, target);
    // The source may have changed while it was being copied: verify the copy.
    if ((await hashTree(target)) !== localHash) {
      await removeTree(target);
      return { exitCode: 1, stderr: `${info.id}: the plugin changed while it was being copied; run propose again` };
    }
  }

  const escapingCopy = await findEscapingSymlinks(target);
  if (escapingCopy.length > 0) {
    await removeTree(target);
    return { exitCode: 1, stderr: `${info.id}: the snapshot contains symlinks that leave it (${escapingCopy.slice(0, 5).join(", ")})` };
  }

  const covering = await d.gate.windowCovering(info.id, args.threadId);
  // The same snapshot proposed again keeps its row, and with it any approval
  // and build state; only the asking thread and window change.
  const earlier = d.store.proposalByDir(target);
  let proposal;
  if (earlier && earlier.pluginId === info.id && earlier.localHash === localHash) {
    d.store.retargetProposal(earlier.id, args.threadId, covering?.id ?? null);
    proposal = d.store.getProposal(earlier.id)!;
  } else {
    proposal = d.store.addProposal({ pluginId: info.id, localHash, snapshotDir: target, threadId: args.threadId, windowId: covering?.id ?? null });
  }
  const approvedBefore = proposal.touchApprovedAt !== null || proposal.loadedAt !== null;
  const allowed = covering !== null || approvedBefore;
  d.store.log("propose", info.id, null, { version: info.version, thread: args.threadId, allowed, snapshot: localHash });

  // Checks run now, on the snapshot, so the human sees them on the proposal's card
  // (they are keyed by the snapshot's own hash and linked to the core's hash at load).
  const checks = await d.gate.checkSnapshot(info.id, localHash, target);
  const blocks = checks && !approvedBefore ? bySeverity(checks, "block") : [];

  if (blocks.length > 0) {
    const why = `${BLOCKED_REASON}: ${summarize(blocks)}`;
    const q = d.store.upsertQueue({
      kind: "proposal",
      contentHash: null,
      pluginId: info.id,
      version: info.version,
      source: `path:${target}`,
      sourceKind: "path",
      rootDir: target,
      gitCommit: null,
      npmIntegrity: null,
      trigger: "propose",
      threadId: args.threadId,
      proposalId: proposal.id,
      reason: why,
    });
    d.changed();
    return { exitCode: 3, stdout: `${info.id}: ${T.proposeBlocked(q.id)}` };
  }

  // Outside a window a clean plugin of the safe class (spec §5.2) needs no touch: the hook will let it in.
  const safeClass = checks !== null && checks.capabilities.length === 0 && bySeverity(checks, "review").length === 0;

  if (!allowed && !safeClass && !d.guarded) {
    const q = d.store.upsertQueue({
      kind: "proposal",
      contentHash: null,
      pluginId: info.id,
      version: info.version,
      source: `path:${target}`,
      sourceKind: "path",
      rootDir: target,
      gitCommit: null,
      npmIntegrity: null,
      trigger: "propose",
      threadId: args.threadId,
      proposalId: proposal.id,
      reason: checks === null ? "window closed; проверки не завершились" : "window closed",
    });
    d.changed();
    return { exitCode: 3, stdout: `${T.proposeClosed(info.id)} (review #${q.id})` };
  }

  try {
    const res = await d.install(target);
    await d.afterInstall?.(target).catch(() => undefined);
    d.changed();
    const detail = agentStatusDetail(res.statusDetail);
    return {
      exitCode: detail !== null ? 3 : 0,
      stdout: `${res.id}@${res.version}: ${res.status}${detail !== null ? ` (${detail})` : ""}`,
    };
  } catch (err) {
    return { exitCode: 1, stderr: `install failed: ${err instanceof Error ? err.message : String(err)}` };
  }
}
