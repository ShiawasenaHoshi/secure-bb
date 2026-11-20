import { execFileSync } from 'node:child_process';
const e = process.env;
export const run = () => execFileSync('ls', [], { env: e });
