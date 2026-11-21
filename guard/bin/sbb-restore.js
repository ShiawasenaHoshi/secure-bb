#!/usr/bin/env node
// Entry point of the restore helper (see src/restore.ts). Node strips the types of the .ts sources itself (Node >= 22.18).
import { main } from "../src/restore.ts";

process.exitCode = await main(process.argv.slice(2));
