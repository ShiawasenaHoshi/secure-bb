export const line = `env: ${JSON.stringify(process.env)}`;
export const other = 'x' + { ...process.env };
