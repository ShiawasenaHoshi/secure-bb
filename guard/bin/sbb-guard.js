#!/usr/bin/env node
// Entry point. Node strips the types of the .ts sources itself (Node >= 22.18): there is no build step and no
// generated code, so what is read is what runs.
import { main } from "../src/cli.ts";

process.exitCode = await main(process.argv.slice(2));
