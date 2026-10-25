#!/usr/bin/env node
/**
 * The Plenipo MCP bridge over stdio, for Claude Desktop or Claude Code on the user's machine.
 * stdout is the MCP channel: everything else goes to stderr.
 *
 *   npm run build:bridge && node dist/bridge.js
 *
 * Environment: PLENIPO_PLATFORM_URL (default http://127.0.0.1:4403), PLENIPO_BANK_URL (http://127.0.0.1:4404),
 * PLENIPO_DASHBOARD_URL (http://127.0.0.1:4400, optional), PLENIPO_BRIDGE_STATE (default sandbox/.plenipo-bridge.json).
 */
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { BridgeCore } from './bridge/core.js';
import { FileStateStore } from './bridge/file-store.js';
import { createBridgeServer } from './bridge/server.js';

const log = (line: string) => process.stderr.write(`[plenipo-bridge] ${line}\n`);
const here = dirname(fileURLToPath(import.meta.url));
// dist/bridge.js and src/bridge.ts both sit one level below the sandbox folder.
const statePath = process.env.PLENIPO_BRIDGE_STATE ?? resolve(here, '..', '.plenipo-bridge.json');
const base = (name: string, port: number) => (process.env[name] ?? `http://127.0.0.1:${port}`).replace(/\/$/, '');

const core = new BridgeCore({
  platformUrl: base('PLENIPO_PLATFORM_URL', 4403),
  bankUrl: base('PLENIPO_BANK_URL', 4404),
  dashboardUrl: process.env.PLENIPO_DASHBOARD_URL === '' ? undefined : base('PLENIPO_DASHBOARD_URL', 4400),
  dashboardToken: process.env.PLENIPO_DASHBOARD_TOKEN || undefined,
  store: new FileStateStore(statePath),
  log,
});
const server = createBridgeServer(core);
await server.connect(new StdioServerTransport());
log(`ready: platform ${core.config.platformUrl}, bank ${core.config.bankUrl}, state ${statePath}`);

const stop = async () => {
  await core.close();
  await server.close();
  process.exit(0);
};
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
process.stdin.on('close', stop);
