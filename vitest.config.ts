import { createRequire } from "node:module";
import { defineConfig } from "vitest/config";

/**
 * The page is rendered in tests by the SDK's harness, which brings its own React. Two copies of React break hooks, so the page's imports of
 * `react` and `react-dom` are pointed at the copies the SDK uses (found from the SDK itself, no path is written here). Without the SDK, nothing changes.
 */
function sdkReactAliases(): Record<string, string> {
  try {
    const here = createRequire(import.meta.url);
    const sdk = createRequire(here.resolve("@get-bb/plugin-sdk/app"));
    const dom = createRequire(sdk.resolve("react-dom/package.json"));
    const react = dom.resolve("react/package.json").replace(/package\.json$/, "");
    const reactDom = sdk.resolve("react-dom/package.json").replace(/package\.json$/, "");
    return { react: react.replace(/\/$/, ""), "react-dom": reactDom.replace(/\/$/, "") };
  } catch {
    return {};
  }
}

export default defineConfig({
  resolve: { alias: sdkReactAliases() },
  // In a real bb the radix packages the components use are the host's; in a test they are read from node_modules. They are inlined so that they take the same React.
  test: { server: { deps: { inline: [/@radix-ui\//, /@floating-ui\//] } } },
});
