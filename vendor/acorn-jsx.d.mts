import type { Parser } from "./acorn.mjs";
declare const jsx: (options?: { allowNamespacedObjects?: boolean; allowNamespaces?: boolean }) => (BaseParser: typeof Parser) => typeof Parser;
export default jsx;
