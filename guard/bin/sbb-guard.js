#!/usr/bin/env node
// Entry point. Node strips the types of the .ts sources itself (Node >= 22.18): there is no build step and no
// generated code, so what is read is what runs.
// `sbb-guard status | head` closes our stdout early: that is not an error.
for (const stream of [process.stdout, process.stderr]) stream.on("error", (err) => { if (err.code !== "EPIPE") throw err; });

import { main } from "../src/cli.ts";

process.exitCode = await main(process.argv.slice(2));
