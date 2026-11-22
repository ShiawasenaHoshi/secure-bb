// The gate's error: a code the page and the RPC layer read, a message, and an optional extra. A leaf module: nothing here imports another module of the plugin,
// so the modules that throw it (batch, watchdog, gate) and the ones that read it need not import each other.

export type GateErrorCode =
  | "not_registered"
  | "blocked"
  | "invalid_code"
  | "conflict"
  | "not_found"
  | "invalid";

export class GateError extends Error {
  constructor(
    readonly code: GateErrorCode,
    message: string,
    readonly extra?: unknown,
  ) {
    super(message);
  }
}
