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
}

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
