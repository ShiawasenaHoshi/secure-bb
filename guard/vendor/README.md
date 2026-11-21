# vendor/

Third-party code used by `src/checks/` to parse plugin source into an AST, and
one data file (the popular-packages list, last section).
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

`guard/src/checks/files.ts` carries the sha256 of the three files above
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

## popular-packages.mjs is data

`popular-packages.mjs` (+ `popular-packages.d.mts`) is the list of popular npm package names that
`src/deps/lookalike.ts` compares dependency names with (Levenshtein ≤ 2, stage 2.3). It holds no code.

| File | Source | Version | License | sha256 |
|---|---|---|---|---|
| `popular-packages.mjs` | [npm-high-impact](https://github.com/wooorm/npm-high-impact) `npmHighImpact` (downloads and dependents on the public npm registry, most impactful first) | 1.13.0, published 2026-06-08 | MIT (`LICENSE.npm-high-impact`) | `f9b806a33d9602f2251ce27eb8ba4e105ae7b0e8d222c82fcf42e51b1b58b65d` |

Taken: the first 5000 names of `npmHighImpact` (17338 in all), lower-cased, in the source's order;
vendored on 2026-11-21. Source and dates are also exported as `POPULAR_SOURCE`. Rebuild: `npm pack npm-high-impact@<version>`,
import `npmHighImpact` from its `index.js`, write the first 5000 names one per line between the two
`export const` markers of the existing file; the header comment and `POPULAR_SOURCE` carry the new version and dates.
The list is a snapshot: a package that became popular after 2026-06-08 is not in it (its lookalikes are missed, the
package itself is not flagged). Refresh it when the vendored parser is updated.

## Known limits

- TypeScript and TSX are parsed directly by acorn-typescript (enum, namespace,
  parameter properties, JSX). Known gaps of that parser: a few constructs it
  rejects (e.g. a generic arrow `<K extends keyof T>(…) =>` after certain code in
  `tasks/views/manage/preset-dialog.tsx` of bb's own plugins; `async <T>(x) =>` in `.ts` files, as in
  `automations.test.ts`, was fixed in stage 2.3: the type-parameter list is blanked out and the file analysed). Such a file is
  `parse-failed` (severity `review`), never a pass. A `.ts` file is retried with
  JSX on and a `.tsx` without it before giving up.
- acorn is configured with `ecmaVersion: "latest"`; syntax newer than the
  vendored version also ends as `parse-failed`.
