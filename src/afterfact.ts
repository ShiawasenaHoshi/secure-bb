// "After the fact" mode, for a bb without the `plugin.activate` hook.
// The plugin's code has ALREADY run when we see it; all we can do is notice a
// new or changed third-party plugin, disable it unless it is approved (or came
// in through an open trust window), and say so honestly.
import type { Gate } from "./gate.js";
import type { InstalledPluginLite } from "./probe.js";
import { isThirdParty } from "./probe.js";
import type { Store } from "./store.js";

export interface AfterFactDeps {
  store: Store;
  gate: Gate;
  listPlugins: () => Promise<InstalledPluginLite[]>;
  disable: (pluginId: string) => Promise<void>;
  hashDir: (dir: string) => Promise<string>;
  now: () => number;
  log: (message: string) => void;
  /** Plugins the core has asked the hook about (so the gate already decided them before they loaded): not for this scanner. */
  vetted?: (pluginId: string) => boolean;
  /** Called when a plugin the hook never saw was disabled here: the hook is not doing its job. */
  onUnvetted?: (pluginIds: string[]) => void;
  /**
   * Guard mode. Approvals are the guard's and are keyed by the CORE's hash (the one the hook was given), never by a hash of ours:
   *  - `coreHash`: the hash the core gave the hook for this plugin and version (null: never seen);
   *  - `guardApproved`: does the guard hold an approval for exactly that hash;
   *  - `noCoreHash`: the version has no core hash, so nothing can be asked of the guard: keep it for a person with a plain reason.
   */
  guard?: {
    coreHash: (pluginId: string, version: string) => string | null;
    guardApproved: (pluginId: string, hash: string) => Promise<boolean>;
    noCoreHash: (p: InstalledPluginLite) => void;
  };
}
/** Why a version is kept when the core's hash is unknown. Plain words; it is NOT a mismatch and not a hard flag. */
export const NO_CORE_HASH_REASON = "не удалось получить хеш ядра: версия загружена без проверки сторожем, одобрить её по хешу нельзя. Удалите её и поставьте заново через «bb secure-bb propose»";

const CACHE_MS = 60_000;
const PENDING = "pending";
const HASH_TIMEOUT_MS = 20_000;

export class AfterFactScanner {
  private running = false;
  private again = false;
  private readonly cache = new Map<string, { hash: string; at: number }>();

  constructor(private readonly d: AfterFactDeps) {}

  /** Coalesces overlapping triggers (events come in bursts). */
  async scan(): Promise<string[]> {
    if (this.running) {
      this.again = true;
      return [];
    }
    this.running = true;
    const disabled: string[] = [];
    try {
      do {
        this.again = false;
        disabled.push(...(await this.scanOnce()));
      } while (this.again);
    } finally {
      this.running = false;
    }
    return disabled;
  }

  private async hashOf(p: InstalledPluginLite): Promise<string> {
    const key = `${p.id}@${p.version}@${p.rootDir}`;
    const hit = this.cache.get(key);
    if (hit && this.d.now() - hit.at < CACHE_MS) return hit.hash;
    const hash = `local:${await this.d.hashDir(p.rootDir)}`;
    this.cache.set(key, { hash, at: this.d.now() });
    return hash;
  }

  /**
   * Remembers which third-party plugins exist right now, WITHOUT reading their code (hashing a large plugin can take a long
   * time). Called at start and when the hook turns out to be dead: whatever is installed at that moment ran before us and is
   * the baseline; whatever appears later is new. A plugin that is not in the baseline when the scan sees it is held at once.
   * (A baseline taken by a slow first scan used to include a plugin installed in the meantime, and so let it through.)
   */
  async snapshotBaseline(): Promise<string[]> {
    const { store } = this.d;
    const present = (await this.d.listPlugins()).filter((p) => isThirdParty(p));
    const added: string[] = [];
    for (const p of present) {
      if (store.hasBaselineRow(p.id)) continue;
      store.markBaseline(p.id, PENDING);
      added.push(p.id);
    }
    if (store.getMeta("afterfact_baseline") === null) {
      store.setMeta("afterfact_baseline", String(this.d.now()));
      store.log("afterfact.baseline", null, null, { plugins: present.map((p) => p.id) });
    } else if (added.length > 0) store.log("afterfact.baseline", null, null, { plugins: added, note: "added to the baseline" });
    return added;
  }

  private async hashWithin(p: InstalledPluginLite): Promise<string> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error(`reading ${p.id} took longer than ${HASH_TIMEOUT_MS / 1000} s`)), HASH_TIMEOUT_MS);
    });
    try {
      return await Promise.race([this.hashOf(p), timeout]);
    } finally {
      clearTimeout(timer);
    }
  }

  private async scanOnce(): Promise<string[]> {
    const { store, gate } = this.d;
    if (store.getMeta("afterfact_baseline") === null) await this.snapshotBaseline();
    const plugins = (await this.d.listPlugins()).filter((p) => isThirdParty(p) && p.enabled);
    const disabled: string[] = [];
    // New plugins first: they are the ones that must be stopped, and they must not wait behind the hashing of old ones.
    const isNew = (p: InstalledPluginLite): boolean => !store.hasBaselineRow(p.id);
    plugins.sort((a, b) => Number(isNew(b)) - Number(isNew(a)));

    for (const p of plugins) {
      if (this.d.vetted?.(p.id)) continue;
      // Allowed but failed to start (the core says `error`): its code did not run, so this is not «after the fact».
      if (p.status === "error") continue;
      const g = this.d.guard;
      if (g) {
        // A version the guard approved by the core's own hash was gated before it loaded: not «after the fact», whatever our local hash says.
        const core = g.coreHash(p.id, p.version);
        if (core !== null && (await g.guardApproved(p.id, core).catch(() => false))) continue;
      }
      let hash: string;
      try {
        hash = await this.hashWithin(p);
      } catch (err) {
        // Cannot read it in time: treat as unknown code, not as safe.
        this.d.log(`cannot hash ${p.id}: ${err instanceof Error ? err.message : String(err)}`);
        if (store.baselineHash(p.id) === PENDING) continue; // an old plugin we could not read yet: try again next time
        await this.hold(p, `unreadable:${p.id}:${p.version}`, disabled);
        continue;
      }
      const base = store.baselineHash(p.id);
      if (base === PENDING) {
        store.markBaseline(p.id, hash); // was there before us: this is its state now
        continue;
      }
      if (base === hash) continue; // unchanged since before secure-bb
      if (this.d.guard) {
        // The guard never gets OUR hash as the version's `contentHash` (it would compare it with the core's and call a lawful plugin forged).
        // The core's hash is known and not approved: the version is held at the guard already (the hook asked it); stop the plugin.
        // The core's hash is unknown: keep a plain entry for a person, and stop the plugin.
        if (this.d.guard.coreHash(p.id, p.version) === null) this.d.guard.noCoreHash(p);
        await this.hold(p, hash, disabled);
        continue;
      }
      const decision = await gate.decide({
        pluginId: p.id,
        version: p.version,
        source: p.source,
        sourceKind: p.source.split(":")[0] ?? "path",
        gitCommit: null,
        npmIntegrity: null,
        rootDir: p.rootDir,
        contentHash: hash,
        trigger: "afterfact",
      });
      if (decision.action !== "proceed") await this.hold(p, hash, disabled);
    }
    if (disabled.length > 0) this.d.onUnvetted?.(disabled);
    return disabled;
  }

  private async hold(p: InstalledPluginLite, hash: string, disabled: string[]): Promise<void> {
    try {
      await this.d.disable(p.id);
      disabled.push(p.id);
      this.d.store.log("afterfact.disable", p.id, hash, { version: p.version, note: "code had already run" });
    } catch (err) {
      this.d.store.log("afterfact.disable-failed", p.id, hash, { message: err instanceof Error ? err.message : String(err) });
    }
  }
}
