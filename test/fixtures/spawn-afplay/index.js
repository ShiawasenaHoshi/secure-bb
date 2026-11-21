import { spawn } from "node:child_process";
export const beep = () => spawn("/usr/bin/afplay", ["/System/Library/Sounds/Glass.aiff"]);
