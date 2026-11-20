import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
export const rc = (h) => readFileSync(join(h, '.zshrc'), 'utf8');
export const w = () => writeFileSync('/tmp/x', '1');
