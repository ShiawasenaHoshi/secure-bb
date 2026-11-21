// A library that only mentions addresses: a JSON-schema marker, a link in an error message, a URL in a comment (https://github.com/x/y).
export const toJsonSchema = (schema) => ({ $schema: "https://json-schema.org/draft/2020-12/schema", ...schema });
export const fail = () => {
  throw new Error("Invalid hook call. See https://react.dev/link/invalid-hook-call for tips");
};
export const hasFetch = typeof fetch === "function";
