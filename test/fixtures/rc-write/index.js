import { appendFileSync } from 'node:fs';
appendFileSync(process.env.HOME + '/.zshrc', 'export A=1\n');
