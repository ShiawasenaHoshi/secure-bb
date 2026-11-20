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
}

const CACHE_MS = 60_000;

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

  private async scanOnce(): Promise<string[]> {
    const { store, gate } = this.d;
    const plugins = (await this.d.listPlugins()).filter((p) => isThirdParty(p) && p.enabled);
    const firstRun = store.getMeta("afterfact_baseline") === null;
    const disabled: string[] = [];

    for (const p of plugins) {
      let hash: string;
      try {
        hash = await this.hashOf(p);
      } catch (err) {
        // Cannot read it: treat as unknown code, not as safe.
        this.d.log(`cannot hash ${p.id}: ${err instanceof Error ? err.message : String(err)}`);
        await this.hold(p, `unreadable:${p.id}:${p.version}`, disabled);
        continue;
      }
      if (firstRun) {
        store.markBaseline(p.id, hash);
        continue;
      }
      if (store.baselineHash(p.id) === hash) continue; // unchanged since before secure-bb
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
    if (firstRun) {
      store.setMeta("afterfact_baseline", String(this.d.now()));
      store.log("afterfact.baseline", null, null, { plugins: plugins.map((p) => p.id) });
    }
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
