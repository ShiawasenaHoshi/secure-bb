// secure-bb — frontend: the secure-bb page (the plugin gate is a section of it) and an always-visible banner
// for open trust windows. Plain React + host theme tokens; no vendored UI,
// no third-party code (this bundle runs in bb's origin, so it stays minimal).
import { definePluginApp } from "@get-bb/plugin-sdk/app";
import { GatePage } from "./app/page";
import { WindowOverlay } from "./app/windows";
export { gapsBySeverity } from "./app/windows";

export default definePluginApp((app) => {
  app.slots.navPanel({
    id: "gate",
    title: "secure-bb",
    icon: "Shield",
    path: "gate",
    component: GatePage,
  });
  app.slots.experimental_appOverlay({ id: "windows", component: WindowOverlay });
});
