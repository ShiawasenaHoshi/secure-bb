import * as cp from 'node:child_process';
export const run = (name, ...a) => cp[name](...a);
