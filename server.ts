// secure-bb — gate for other plugins' code. Backend entry.
//
// Zero runtime dependencies (node:* and the bb SDK only): this plugin is the
// root of trust, so it ships no third-party code. Policy and secrets live in
// its own SQLite database, never in plugin settings (anyone can change those
// through the unauthenticated API, and secret settings are plain files).
import { type BbPluginApi } from "@get-bb/plugin-sdk";
import { rpcContract } from "./src/contract.js";
import { createCore } from "./src/rpc/core.js";
import { createServices } from "./src/rpc/services.js";
import { createGuardHelpers, type RpcCtx } from "./src/rpc/guard-helpers.js";
import { pageRpc } from "./src/rpc/page.js";
import { trustRpc } from "./src/rpc/trust.js";
import { agentsRpc } from "./src/rpc/agents.js";
import { queueRpc } from "./src/rpc/queue.js";
import { watchRpc } from "./src/rpc/watch.js";
import { skillsRpc } from "./src/rpc/skills.js";
import { settingsRpc } from "./src/rpc/settings.js";
import { policyRpc } from "./src/rpc/policy.js";
import { registerCli } from "./src/rpc/cli.js";
import { startBackground } from "./src/rpc/background.js";

export { rpcContract };
export type SecureBbRpc = typeof rpcContract;

export default async function plugin(bb: BbPluginApi) {
  const core = await createCore(bb);
  const services = await createServices(core);
  const helpers = createGuardHelpers({ ...core, ...services });
  const c: RpcCtx = { ...core, ...services, ...helpers };

  c.bb.rpc.register(
    rpcContract,
    c.withGuardTouch({
      ...pageRpc(c),
      ...trustRpc(c),
      ...agentsRpc(c),
      ...queueRpc(c),
      ...watchRpc(c),
      ...skillsRpc(c),
      ...settingsRpc(c),
      ...policyRpc(c),
    }),
  );
  registerCli(c);
  startBackground(c);

  const { alive } = c;
  bb.onDispose(() => {
    // The database handle is closed by the host; the only thing left is the note that this was an orderly stop.
    try {
      alive.stop();
    } catch {
      /* the database may already be closed */
    }
  });
}
