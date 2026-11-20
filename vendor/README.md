# vendor/

Third-party code used by `src/checks/` to parse plugin source into an AST.
This is the **only** exception to secure-bb's "zero runtime dependencies"
rule: Node has no built-in JavaScript parser, and a regex scanner is easy to
get around. The files are copied byte for byte from the npm tarballs
(no install step, no transitive dependencies, nothing fetched at runtime);
`test/vendor.test.ts` checks the hashes below, so any change fails the tests.

| File | Package | Version | License | sha256 |
|---|---|---|---|---|
| `acorn.mjs` (+ `acorn.d.mts`) | [acorn](https://github.com/acornjs/acorn) `dist/acorn.mjs` | 8.19.0 | MIT (`LICENSE.acorn`) | `76254fc76529713b4dfd2532972d17a991ffd9aafeebb1f977445b5506b9fb0b` |
| `acorn-typescript.mjs` (+ `acorn-typescript.d.mts`) | [@sveltejs/acorn-typescript](https://github.com/sveltejs/acorn-typescript) `index.js` | 1.0.13 | MIT (`LICENSE.acorn-typescript`) | `e8e9281a975668bddb679c6cdc266e699cc69ddfeada1e4b3e4dc6def9bbe0e7` |
| `acorn-jsx.mjs` (+ `acorn-jsx.d.mts`) | [acorn-jsx](https://github.com/acornjs/acorn-jsx) `index.js` + `xhtml.js` | 5.3.2 | MIT (`LICENSE.acorn-jsx`) | `699f555f7886852da766df6ffe0d8e7787211f1e72acda7a20e76c981dad2e67` |

Upstream originals (npm tarballs): `acorn-jsx@5.3.2` `index.js` sha256
`5ab23edca59b840bc26ba711131a5b649540b70da53d70ae1bbcdb13480c1aa1`;
`@sveltejs/acorn-typescript@1.0.13` `index.js` sha256
`e27fb4b6946cc74cc6f32d6c43f8d082ebc198cd8a2ef3ccc40101fded57044e`.

acorn-walk is no longer vendored: the walker over the AST is `walkAst` in
`src/checks/ast.ts` (it also has to know JSX and TypeScript nodes, which
acorn-walk does not).

## acorn-typescript.mjs differs from the original in one line

The package imports `acorn` by bare name, which does not resolve inside a plugin
bundle. Line 2, `import * as acornNamespace from "acorn";`, is replaced by
`import * as acornNamespace from "./acorn.mjs";` (the vendored copy above).
Nothing else was changed; `diff` against the tarball's `index.js` shows that one line.

## Built-in hash exemption

`src/checks/files.ts` carries the sha256 of the three files above
(`KNOWN_VENDORED_SHA256`): a file with exactly these bytes is not reported as
`minified` (Unicode tables look dense). The list is in the checker, not read from
a checked tree's own README, so a plugin cannot vouch for its own files;
`test/checks.test.ts` verifies that every hash in the list is in this README.

## acorn-jsx.mjs is a wrapper

acorn-jsx is CommonJS (`require('./xhtml')`), which does not load from an ES
module bundle. `acorn-jsx.mjs` embeds the two original files **unchanged**,
each inside a function that supplies `module` / `require`, between
`BEGIN`/`END` markers, and ends with `export default`. Nothing inside the
markers was edited. To rebuild: concatenate header, `xhtml.js`, the glue
lines and `index.js` as in the existing file; the result must be identical.

## Known limits

- TypeScript and TSX are parsed directly by acorn-typescript (enum, namespace,
  parameter properties, JSX). Known gaps of that parser: a few constructs it
  rejects (e.g. a generic arrow `<K extends keyof T>(…) =>` after certain code in
  `tasks/views/manage/preset-dialog.tsx` of bb's own plugins). Such a file is
  `parse-failed` (severity `review`), never a pass. A `.ts` file is retried with
  JSX on and a `.tsx` without it before giving up.
- acorn is configured with `ecmaVersion: "latest"`; syntax newer than the
  vendored version also ends as `parse-failed`.
