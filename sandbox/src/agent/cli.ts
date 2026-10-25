/**
 * The LLM agent from the command line, against a running sandbox (`npm run sandbox`).
 *
 *   npm run agent -- "pay this month's utility bills"
 *   npm run agent -- --person luca --auto-approve "pay the water bill only"
 *   npm run agent -- --mandate latest "what is my balance?"     (or the short id shown on the platform page)
 *
 * Without --mandate it asks the platform for a mandate (template --preset, default utilities) and waits
 * for the person to approve it in the wallet, unless --auto-approve is given.
 */
import Anthropic from '@anthropic-ai/sdk';
import { DEFAULT_PORTS, optionsFromEnv } from '../config.js';
import { SandboxAgentClient } from './client.js';
import { DEFAULT_MODEL, runLlmAgent } from './llm.js';

function flag(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : undefined;
}
const has = (name: string) => process.argv.includes(`--${name}`);
const valued = new Set(['person', 'mandate', 'preset', 'model']);
const words = process.argv.slice(2).filter((a, i, all) => !a.startsWith('--') && !(i > 0 && all[i - 1].startsWith('--') && valued.has(all[i - 1].slice(2))));
const task = words.join(' ').trim() || "Pay this month's utility bills.";

if (!process.env.ANTHROPIC_API_KEY) {
  console.log(`The LLM agent needs an Anthropic API key.

  export ANTHROPIC_API_KEY=sk-ant-...        # from https://platform.claude.com/
  export PLENIPO_AGENT_MODEL=${DEFAULT_MODEL}   # optional, this is the default
  npm run agent -- "${task}"

Without a key, the scripted agent shows the same flows deterministically:

  npm run scenarios -- --attach`);
  process.exit(0);
}

const o = optionsFromEnv();
const host = o.host ?? '127.0.0.1';
const url = (n: keyof typeof DEFAULT_PORTS) => `http://${host}:${o.ports?.[n] ?? DEFAULT_PORTS[n]}`;
const client = new SandboxAgentClient({ platform: url('platform'), wallet: url('wallet'), bank: url('bank'), dashboard: url('dashboard') });
const person = flag('person') ?? 'maria';
const model = flag('model') ?? process.env.PLENIPO_AGENT_MODEL ?? DEFAULT_MODEL;

try {
  await fetch(`${url('platform')}/api/info`, { signal: AbortSignal.timeout(3000) });
} catch {
  console.error(`No sandbox at ${url('platform')}. Start it first with: npm run sandbox`);
  process.exit(1);
}

let mandateId = flag('mandate');
if (mandateId) {
  // Accept "latest" or the short id shown on the platform page.
  const list = (await (await fetch(`${url('platform')}/api/mandates`)).json()) as Array<{ id: string; state: string; depth: number }>;
  const active = list.filter((m) => m.state === 'active' && m.depth === 0);
  const found = mandateId === 'latest' ? active.at(-1) : list.find((m) => m.id.startsWith(mandateId!));
  if (!found) {
    console.error(`No mandate ${mandateId} at the platform.`);
    process.exit(1);
  }
  mandateId = found.id;
} else {
  const req = await client.requestMandate({ agentName: 'Claude bill assistant', preset: flag('preset') ?? 'utilities' });
  const clientId = new URL(req.authorization_url).searchParams.get('client_id')!;
  if (has('auto-approve')) {
    await client.walletDecide(req.request_uri, clientId, person, 'approve');
  } else {
    console.log(`\nThe agent asked for a mandate. Approve it in the wallet:\n\n  ${req.wallet_url ?? req.authorization_url}\n\n(or scan the QR code at ${url('platform')}/requests/${req.request_id})\n`);
  }
  const s = await client.waitForApproval(req.request_id, 10 * 60_000);
  if (s.state !== 'active') {
    console.log(`No mandate: the request ended as ${s.state}${s.error ? ` (${s.error})` : ''}. The agent cannot act.`);
    process.exit(1);
  }
  mandateId = s.mandate_id;
  console.log(`Mandate ${mandateId} approved.\n`);
}

const anthropic = new Anthropic();
console.log(`Task: ${task}\nModel: ${model}\n`);
await client.note('note', { text: `LLM agent (${model}) starts: "${task}"` });
const result = await runLlmAgent({
  client,
  mandateId,
  task,
  model,
  createMessage: (params) => anthropic.messages.create(params),
  log: (line) => console.log(line),
});
console.log(`\n${result.calls.length} tool calls, ${result.calls.filter((c) => c.outcome.decision === 'DENY').length} denied by the bank.`);
await client.close();
