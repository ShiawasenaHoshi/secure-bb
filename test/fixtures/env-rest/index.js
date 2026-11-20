const { HOME, ...rest } = process.env;
export default [HOME, JSON.stringify(rest)];
