#!/usr/bin/env node
// kya-study: the case-study kit's command line. Everything is local; see README.md.
import { main } from "./main.js";

process.exitCode = await main(process.argv.slice(2));
