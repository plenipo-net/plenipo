/**
 * Starts the whole sandbox and prints where everything is. Stop with Ctrl-C.
 *
 *   npm run sandbox
 */
import { optionsFromEnv } from './config.js';
import { hostRoutes, openPaths, startFront, type RunningFront } from './front.js';
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
${sandbox.agentGateway ? `  Remote MCP     ${u.agent}${sandbox.agentGateway.mcpPath}        one bridge per session; watch one at ${u.dashboard}/demo/<code>\n` : ''}
  Identities: PID iss ${sandbox.identities.pidIssuer}, platform ${sandbox.platform.clientId}, bank ${sandbox.identities.bankHost}
  Status cache at the bank: ${sandbox.statusCacheSeconds} s (revocation latency)

  In another terminal:
    npm run scenarios -- --attach                 all scripted scenarios, live on the dashboard
    npm run agent -- "pay this month's utility bills"   the LLM agent (needs ANTHROPIC_API_KEY)
`);

// Hosted: one public port that dispatches by host name (SANDBOX_DOMAIN, SANDBOX_FRONT_PORT).
let front: RunningFront | undefined;
const domain = process.env.SANDBOX_DOMAIN;
if (domain && process.env.SANDBOX_FRONT_PORT) {
  front = await startFront({
    host: process.env.SANDBOX_FRONT_HOST ?? '0.0.0.0',
    port: Number(process.env.SANDBOX_FRONT_PORT),
    routes: hostRoutes(domain, sandbox.urls),
    basicAuth: process.env.SANDBOX_DEMO_LOGIN || undefined,
    open: openPaths(domain),
    clientIpHeader: process.env.SANDBOX_CLIENT_IP_HEADER || undefined,
  });
  console.log(`  Front door on ${front.url} for ${domain} and its subdomains${process.env.SANDBOX_DEMO_LOGIN ? ' (demo login on)' : ''}\n`);
}

// A public sandbox starts clean every day: at SANDBOX_RESTART_AT (UTC, HH:MM) the process exits and
// the platform starts it again.
const restartAt = process.env.SANDBOX_RESTART_AT;
if (restartAt && /^\d{2}:\d{2}$/.test(restartAt)) {
  const [hh, mm] = restartAt.split(':').map(Number);
  const now = new Date();
  const next = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate(), hh, mm));
  if (next <= now) next.setUTCDate(next.getUTCDate() + 1);
  setTimeout(() => {
    console.log('Daily restart: the sandbox starts again with a clean state.');
    void stop();
  }, next.getTime() - now.getTime()).unref();
}

let stopping = false;
async function stop() {
  if (stopping) return;
  stopping = true;
  console.log('\nStopping...');
  await front?.close();
  await sandbox.close();
  process.exit(0);
}
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
