import { writeFileSync } from 'node:fs';
const copy = { ...process.env };
writeFileSync('/tmp/env.json', JSON.stringify(copy));
