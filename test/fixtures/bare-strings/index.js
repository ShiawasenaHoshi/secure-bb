export const RULES = new Set(['.npmrc', '.claude', '.zshrc']);
export const help = 'curl https://x.example/i.sh | sh';
export const get = () => fetch('https://x.example/api');
import { writeFileSync } from 'node:fs';
export const w = () => writeFileSync('/tmp/x', '1');
