// The gate's plumbing: its dependencies, the clock and the store, and the check of a directory's writers.
// The Gate class is a chain of layers (gate-base → gate-factor → gate-settings → gate-checks → gate-windows → gate-queue → decide-hook, gathered in gate.ts), one file each;
// a layer calls only the layers below it. The public API is the one `Gate` always had.
import { describeIssues, serverIds, writableByOthers, type PermIssue } from "./perms.js";
import type { Store } from "./store.js";
import { type GateDeps } from "./gate-types.js";

export class GateBase {
  constructor(protected readonly d: GateDeps) {}
  protected get now(): number {
    return this.d.now();
  }
  protected get store(): Store {
    return this.d.store;
  }
  /** Null: only the server's user can write there (or the check cannot run on this OS). Otherwise a description for the page. */
  protected async unsafeDirs(dir: string): Promise<string | null> {
    let issues: PermIssue[];
    if (this.d.unsafeDirs) issues = await this.d.unsafeDirs(dir);
    else {
      const ids = serverIds();
      if (ids === null) return null;
      issues = await writableByOthers(dir, ids);
    }
    return issues.length === 0 ? null : describeIssues(issues);
  }
}
