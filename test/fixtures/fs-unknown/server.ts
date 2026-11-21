import { readFileSync } from "node:fs";
export default function (bb: any): void {
  // A sound player: reads a settings file the code does not name by a path.
  const path = String(bb.settings?.soundFile);
  bb.log.info(readFileSync(path, "utf8"));
}
