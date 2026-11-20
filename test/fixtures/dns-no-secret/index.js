import dns from 'node:dns/promises';
export const look = () => dns.resolve(`a.x.example`);
export const h = process.env.HOME;
