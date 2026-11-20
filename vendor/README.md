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
| `walk.mjs` (+ `walk.d.mts`) | [acorn-walk](https://github.com/acornjs/acorn) `dist/walk.mjs` | 8.3.5 | MIT (`LICENSE.acorn-walk`) | `24bc7ea73dcc319360090f4849746b7493bf234f951ea99ae0b89105981b1b42` |
| `acorn-jsx.mjs` (+ `acorn-jsx.d.mts`) | [acorn-jsx](https://github.com/acornjs/acorn-jsx) `index.js` + `xhtml.js` | 5.3.2 | MIT (`LICENSE.acorn-jsx`) | `699f555f7886852da766df6ffe0d8e7787211f1e72acda7a20e76c981dad2e67` |

Upstream originals: `acorn-jsx@5.3.2` `index.js` sha256
`5ab23edca59b840bc26ba711131a5b649540b70da53d70ae1bbcdb13480c1aa1`.

## acorn-jsx.mjs is a wrapper

acorn-jsx is CommonJS (`require('./xhtml')`), which does not load from an ES
module bundle. `acorn-jsx.mjs` embeds the two original files **unchanged**,
each inside a function that supplies `module` / `require`, between
`BEGIN`/`END` markers, and ends with `export default`. Nothing inside the
markers was edited. To rebuild: concatenate header, `xhtml.js`, the glue
lines and `index.js` as in the existing file; the result must be identical.

## Known limits

- TypeScript is reduced to JavaScript with `stripTypeScriptTypes` from
  `node:module` (type-only syntax; positions are kept). It does not handle
  `enum`/`namespace`, nor JSX inside `.tsx`: such a file is reported as
  `parse-failed` (severity `review`) unless it parses as plain JSX.
- acorn is configured with `ecmaVersion: "latest"`; syntax newer than the
  vendored version also ends as `parse-failed`.
