#!/usr/bin/env node
/** stdio entry: `npx @kya-brasil/mcp`, or `node dist/index.js` in a container. */
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createKyaMcpServer } from "./server.js";

const key = process.env.KYA_PRIVATE_KEY?.trim();
if (key && !/^0x[0-9a-fA-F]{64}$/.test(key)) {
  console.error("KYA_PRIVATE_KEY must be a 0x-prefixed 32-byte hex key; starting without paid tools");
}
const { server } = createKyaMcpServer({
  baseUrl: process.env.KYA_BASE_URL?.trim() || undefined,
  privateKey: key && /^0x[0-9a-fA-F]{64}$/.test(key) ? (key as `0x${string}`) : undefined
});
await server.connect(new StdioServerTransport());
