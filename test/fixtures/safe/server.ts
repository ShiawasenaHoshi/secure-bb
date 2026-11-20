import type { BbPluginApi } from '@get-bb/plugin-sdk';
export default function (bb: BbPluginApi): void {
  const n: number = 1;
  bb.log.info(String(n));
}
