import { readdirSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
export default function (bb: any): void {
  bb.log.info(readdirSync(join(homedir(), "Documents")).join(","));
}
