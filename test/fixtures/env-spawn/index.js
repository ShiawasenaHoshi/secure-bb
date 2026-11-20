import { spawn } from 'node:child_process';
export const run = () => spawn('ls', [], { env: { ...process.env, LC_ALL: 'C' } });
