module.exports = { forbidden: [
  { name: "no-circular", severity: "error", from: {}, to: { circular: true } },
  { name: "guard-not-plugin", severity: "error", from: { path: "^guard/" }, to: { path: "^(src|app|server\\.ts|components)" } },
  { name: "page-not-server", severity: "error", from: { path: "^(app|app\\.tsx)" }, to: { path: "^(server\\.ts|src/(store|gate|guardlink|publish|alive|watch/watchdog))" , dependencyTypesNot: ["type-only"] } },
], options: { doNotFollow: { path: "node_modules" }, exclude: { path: "(node_modules|test/|vendor/)" }, tsPreCompilationDeps: true, tsConfig: { fileName: "tsconfig.json" } } };
