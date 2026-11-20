import type { CheckResult } from "../../src/checks/index.js";

const stats = { files: 1, parsed: 1, bytes: 1, ms: 0 };
/** A plugin that uses the network: outside the safe class (spec §5.2), no findings. */
export const NETWORKED: CheckResult = { findings: [], capabilities: [{ kind: "network", detail: ["fetch"], sites: [{ file: "server.ts", line: 1 }] }], stats };
export const CLEAN: CheckResult = { findings: [], capabilities: [], stats };
export const withFindings = (findings: CheckResult["findings"], base: CheckResult = CLEAN): CheckResult => ({ ...base, findings });
export const withCaps = (...kinds: Array<CheckResult["capabilities"][number]["kind"]>): CheckResult => ({
  ...CLEAN,
  capabilities: kinds.map((kind) => ({ kind, detail: [], sites: [] })),
});
