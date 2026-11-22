// The tree of threads as the gate and the monitors ask it (the host's `threads` calls, or a fake in the tests). A leaf module.

export interface ThreadTree {
  /** Ancestors of a thread, parent first. */
  ancestors(threadId: string): Promise<string[]>;
  /** Every thread below a thread. */
  descendants(threadId: string): Promise<string[]>;
}
