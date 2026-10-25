/**
 * Runs the scripted scenarios and prints PASS/FAIL for each.
 *
 *   npm run scenarios                 boots its own services on free ports, runs everything, exits
 *   npm run scenarios -- --attach     runs against a sandbox started with `npm run sandbox` (the dashboard shows it)
 *   npm run scenarios -- replay expired   runs only the named scenarios
 */
import { SandboxAgentClient } from './agent/client.js';
import { bankAudiences, DEFAULT_IDENTITIES, DEFAULT_PORTS, optionsFromEnv } from './config.js';
import { startSandbox, type Sandbox } from './sandbox.js';
import { formatResult, runScenario, SCENARIOS, type ScenarioEnv } from './scenarios.js';

const args = process.argv.slice(2);
const attach = args.includes('--attach');
const only = args.filter((a) => !a.startsWith('--'));
const unknown = only.filter((id) => !SCENARIOS.some((s) => s.id === id));
if (unknown.length) {
  console.error(`Unknown scenario(s): ${unknown.join(', ')}. Available: ${SCENARIOS.map((s) => s.id).join(', ')}`);
  process.exit(2);
}

let sandbox: Sandbox | undefined;
let env: ScenarioEnv;
if (attach) {
  const o = optionsFromEnv();
  const host = o.host ?? '127.0.0.1';
  const url = (n: keyof typeof DEFAULT_PORTS) => `http://${host}:${o.ports?.[n] ?? DEFAULT_PORTS[n]}`;
  const bankHost = o.identities?.bankHost ?? DEFAULT_IDENTITIES.bankHost;
  env = {
    client: new SandboxAgentClient({ platform: url('platform'), wallet: url('wallet'), bank: url('bank'), dashboard: url('dashboard') }),
    bankHost,
    audiences: bankAudiences(bankHost),
    urls: { pid: url('pid'), bank: url('bank'), platform: url('platform'), wallet: url('wallet') },
    adminToken: o.adminToken,
    statusCacheSeconds: o.statusCacheSeconds ?? 2,
  };
  console.log(`Attaching to the sandbox on ${url('dashboard')} ...`);
} else {
  const ports = { dashboard: 0, pid: 0, wallet: 0, platform: 0, bank: 0 };
  sandbox = await startSandbox({ ...optionsFromEnv(), ports, statusCacheSeconds: 1 });
  env = {
    client: new SandboxAgentClient({ platform: sandbox.urls.platform, wallet: sandbox.urls.wallet, bank: sandbox.urls.bank, dashboard: sandbox.urls.dashboard }),
    bankHost: sandbox.identities.bankHost,
    audiences: sandbox.bank.audiences,
    urls: sandbox.urls,
    adminToken: sandbox.adminToken,
    statusCacheSeconds: sandbox.statusCacheSeconds,
  };
}

const color = process.stdout.isTTY;
const selected = only.length ? SCENARIOS.filter((s) => only.includes(s.id)) : SCENARIOS;
const results = [];
for (const s of selected) {
  const r = await runScenario(s, env);
  results.push(r);
  console.log(formatResult(r, color) + '\n');
}
await env.client.close();
await sandbox?.close();

const passed = results.filter((r) => r.pass).length;
console.log(`${passed}/${results.length} scenarios passed`);
process.exit(passed === results.length ? 0 : 1);
