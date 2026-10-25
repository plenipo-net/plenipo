/**
 * Starts the whole sandbox and prints where everything is. Stop with Ctrl-C.
 *
 *   npm run sandbox
 */
import { optionsFromEnv } from './config.js';
import { startSandbox, type Sandbox } from './sandbox.js';

let sandbox: Sandbox;
try {
  sandbox = await startSandbox(optionsFromEnv());
} catch (e) {
  const err = e as NodeJS.ErrnoException & { port?: number };
  if (err.code === 'EADDRINUSE') {
    console.error(`Port ${err.port ?? ''} is already in use: is another sandbox running? Stop it, or set SANDBOX_PORT_BASE (e.g. 5400).`);
  } else {
    console.error(`The sandbox could not start: ${err.message}`);
  }
  process.exit(1);
}
const u = sandbox.publicUrls;
const b = (s: string) => (process.stdout.isTTY ? `\x1b[1m${s}\x1b[0m` : s);
console.log(`
${b('Plenipo sandbox is running')}

  Dashboard      ${u.dashboard}        <- open this first
  Wallet         ${u.wallet}        Maria Rossi and Luca Bianchi, one PID each
  Agent platform ${u.platform}        my mandates, new requests, revoke
  Bank           ${u.bank}        accounts; MCP at ${sandbox.urls.bank}/mcp, REST at /psd2/v1
  PID provider   ${u.pid}        PIDs and their status list

  Identities: PID iss ${sandbox.identities.pidIssuer}, platform ${sandbox.platform.clientId}, bank ${sandbox.identities.bankHost}
  Status cache at the bank: ${sandbox.statusCacheSeconds} s (revocation latency)

  In another terminal:
    npm run scenarios -- --attach                 all scripted scenarios, live on the dashboard
    npm run agent -- "pay this month's utility bills"   the LLM agent (needs ANTHROPIC_API_KEY)
`);

let stopping = false;
async function stop() {
  if (stopping) return;
  stopping = true;
  console.log('\nStopping...');
  await sandbox.close();
  process.exit(0);
}
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
