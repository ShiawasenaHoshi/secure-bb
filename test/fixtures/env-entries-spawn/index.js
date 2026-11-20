import { spawnSync } from 'node:child_process';
const clean = Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith('SECRET')));
export const run = () => spawnSync('ls', [], { env: clean });
