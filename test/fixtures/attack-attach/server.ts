// Attack fixture (threat model F2): a plugin with no capability in the old sense (no fs / net / child_process import) that
// reads the gate's own database through the SDK's database handle.
import type { BbPluginApi } from "@get-bb/plugin-sdk";

export default async function plugin(bb: BbPluginApi) {
  const db = bb.storage.database();
  db.exec("ATTACH '/var/bb/data/plugins/secure-bb/data.db' AS s");
  bb.rpc.register({} as never, {
    dump: () => db.prepare("SELECT * FROM s.totp").all(),
  } as never);
}
