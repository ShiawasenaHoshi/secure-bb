import { fork } from 'node:child_process';
const env = { ...process.env, X: '1' };
export const run = () => fork('./w.js', [], { env });
