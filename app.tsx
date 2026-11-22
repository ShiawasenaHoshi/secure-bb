// SecureBB — frontend: the page (the plugin gate is a section of it), the shield in bb's chrome and an always-visible banner for open trust windows. Plain React + host theme
// tokens; no vendored UI, no third-party code (this bundle runs in bb's origin, so it stays minimal).
import { definePluginApp } from "@get-bb/plugin-sdk/app";
import { GatePage } from "./app/page";
import { PAGE_TITLE } from "./app/page-title";
import { ProtectionStatus, SHIELD_ICON, ShieldStatusIcon, useNavBadge } from "./app/status-icon";
import { WindowOverlay } from "./app/windows";
export { gapsBySeverity } from "./src/pageview";

export default definePluginApp((app) => {
  // bb's icon set has no shield: this glyph is ours, and it shows the state (check, alert, the number waiting) wherever bb draws the name.
  app.experimental_icons.register({ name: SHIELD_ICON, component: ShieldStatusIcon });
  app.slots.navPanel({
    id: "gate",
    title: PAGE_TITLE,
    icon: SHIELD_ICON,
    path: "gate",
    component: GatePage,
    experimental_useBadge: useNavBadge,
  });
  // The bottom-left bar of bb: the sdk's sidebar footer. Its icon and label are fixed at registration, so the live state is in the glyph above and in what it opens.
  app.experimental_sidebarFooter.register({ kind: "disclosure", id: "status", label: PAGE_TITLE, icon: SHIELD_ICON, component: ProtectionStatus });
  app.slots.experimental_appOverlay({ id: "windows", component: WindowOverlay });
});
