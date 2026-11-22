// What the PAGE (`app.tsx`, built by bb as a browser bundle) may reach. The page runs in the browser: nothing it reaches may import `node:*`, the guard's analyser,
// its database or sockets, or a server module. Type-only imports are erased by the bundler, so this config does not count them (`tsPreCompilationDeps: false`);
// the main config (.dependency-cruiser.cjs) counts them, for cycles. Tests: test/dependency-rules.test.ts (rules) and test/browser-build.test.ts (a real build).
//
// The guard files the page may reach are listed here and are LEAVES (no imports, or only types): add one only after checking it imports nothing of Node.
module.exports = { forbidden: [
  {
    name: "page-reaches-only-leaves-of-the-guard",
    severity: "error",
    comment: "From app.tsx only these guard files may be reached: lift.ts, github-address.ts, session-rules.ts, checks/sdk-rights.ts, checks/types.ts. The rest imports Node (node:fs, node:path, node:crypto, node:module) or the analyser.",
    from: { path: "^app\\.tsx$" },
    to: { path: "^guard/", pathNot: "^guard/src/(lift|github-address|session-rules)\\.ts$|^guard/src/checks/(sdk-rights|types)\\.ts$", reachable: true },
  },
  {
    name: "page-reaches-no-server-module",
    severity: "error",
    comment: "The page does not reach the server's modules through any chain (a type import is erased and does not count).",
    from: { path: "^app\\.tsx$" },
    to: { path: "^(server\\.ts|src/(store|gate|alive|afterfact|batch|journal|probe|propose|overview)\\.ts|src/(watch/watchdog|publish/|skills/(guard|store)|taint/monitor))", reachable: true },
  },
], options: { doNotFollow: { path: "node_modules" }, exclude: { path: "(node_modules|test/|vendor/)" }, tsPreCompilationDeps: false, tsConfig: { fileName: "tsconfig.json" } } };
