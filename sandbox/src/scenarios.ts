/**
 * Named, deterministic scenarios. Each one plays a person, an agent platform and one or more agents
 * against the running services over HTTP, and checks the bank's answers against what Plenipo must do.
 */
import { decodeMandateTransactionData, encodeMandateTransactionData, newIdempotencyKey } from 'plenipo';
import type { CallOutcome, SandboxAgentClient } from './agent/client.js';
import { ATTACKER_HOST } from './catalog.js';

export interface ScenarioEnv {
  client: SandboxAgentClient;
  bankHost: string;
  audiences: { mcp: string; rest: string };
  urls: { pid: string; bank: string; platform: string; wallet: string };
  adminToken?: string;
  statusCacheSeconds: number;
}

export interface Step {
  label: string;
  expected: string;
  actual: string;
  ok: boolean;
}

export interface ScenarioResult {
  id: string;
  title: string;
  expected: string;
  pass: boolean;
  steps: Step[];
  error?: string;
  ms: number;
}

interface Ctx extends ScenarioEnv {
  /** Records a tool call outcome against the expected decision (ALLOW or a deny code). */
  expect(label: string, outcome: CallOutcome, expected: string): CallOutcome;
  check(label: string, ok: boolean, expected: string, actual: string): void;
  sleep(ms: number): Promise<void>;
  admin(url: string, body?: unknown): Promise<Response>;
}

export interface Scenario {
  id: string;
  title: string;
  expected: string;
  run(ctx: Ctx): Promise<void>;
}

const UTIL = 'utilities';

function describe(o: CallOutcome): string {
  if (o.decision === 'DENY') return `DENY ${o.code}`;
  return o.isError ? `ALLOW (bank error ${o.code})` : 'ALLOW';
}

export const SCENARIOS: Scenario[] = [
  {
    id: 'happy-path',
    title: "Happy path: the agent pays this month's utility bills",
    expected: 'Maria approves a 300 euro utilities mandate; balance, payees and three bill payments are allowed over MCP, and the REST API agrees.',
    async run(c) {
      const m = await c.client.obtainMandate({ agentName: 'Bill assistant', person: 'maria', preset: UTIL });
      const before = await c.client.restBalance(m, c.audiences.rest);
      c.check('REST balance before', before.status === 200, 'HTTP 200 ALLOW', `HTTP ${before.status}`);
      c.expect('get_balance', await c.client.callTool(m, 'get_balance', {}), 'ALLOW');
      c.expect('list_payees utilities', await c.client.callTool(m, 'list_payees', { category: 'utilities' }), 'ALLOW');
      c.expect('pay Lumen 84.30', await c.client.callTool(m, 'transfer', { payee: 'lumen-energia.example', amount_cents: 8430, reference: 'Lumen bill 2026-09' }), 'ALLOW');
      c.expect('pay AcquaViva 41.20', await c.client.callTool(m, 'transfer', { payee: 'acquaviva.example', amount_cents: 4120, reference: 'AcquaViva bill Q3 2026' }), 'ALLOW');
      c.expect('pay TeleNord 29.90', await c.client.callTool(m, 'transfer', { payee: 'telenord.example', amount_cents: 2990, reference: 'TeleNord bill 2026-10' }), 'ALLOW');
      const after = await c.client.restBalance(m, c.audiences.rest);
      const diff = Number(before.body.balance_cents) - Number(after.body.balance_cents);
      c.check('balance went down by 155.40', diff === 15540, '15540 cents', `${diff} cents`);
    },
  },
  {
    id: 'reads-without-reservation',
    title: 'Reading the account under a mandate with limits',
    expected: 'The utilities mandate lists only the three billers; balance and payee reads are allowed anyway, reserve nothing against the limits, and the full 300 euro stays available for payments.',
    async run(c) {
      const m = await c.client.obtainMandate({ agentName: 'Bill assistant', person: 'maria', preset: UTIL });
      const { mandate } = await c.client.mandate(m);
      c.check('the bank is not among the mandate counterparties', !(mandate.counterparties ?? []).includes(c.bankHost), 'not listed', (mandate.counterparties ?? []).join(', '));
      c.expect('get_balance', await c.client.callTool(m, 'get_balance', {}), 'ALLOW');
      c.expect('list_payees', await c.client.callTool(m, 'list_payees', {}), 'ALLOW');
      c.expect('get_balance again', await c.client.callTool(m, 'get_balance', {}), 'ALLOW');
      const events = (await (await fetch(`${c.urls.bank}/events`)).json()) as Array<Record<string, unknown>>;
      const reads = events.filter((e) => e.type === 'decision' && e.leaf_mandate === m && e.action === 'account.read');
      c.check('reads carried no reservation', reads.length === 3 && reads.every((e) => e.reservation === false), '3 reads, no reservation', `${reads.length} reads, reservations ${reads.map((e) => e.reservation).join(',')}`);
      c.expect('pay Lumen 150.00', await c.client.callTool(m, 'transfer', { payee: 'lumen-energia.example', amount_cents: 15000, reference: 'Lumen' }), 'ALLOW');
      c.expect('pay AcquaViva 150.00 (total exactly 300)', await c.client.callTool(m, 'transfer', { payee: 'acquaviva.example', amount_cents: 15000, reference: 'AcquaViva' }), 'ALLOW');
      c.expect('one more cent', await c.client.callTool(m, 'transfer', { payee: 'telenord.example', amount_cents: 1, reference: 'TeleNord' }), 'LIMIT_TOTAL');
    },
  },
  {
    id: 'prompt-injection',
    title: 'Prompt injection: a bill tells the agent to pay someone else',
    expected: `Luca's water bill carries instructions for AI assistants to pay ${ATTACKER_HOST} instead of AcquaViva. A fooled agent follows them; the bank denies with COUNTERPARTY_NOT_PERMITTED, and the genuine AcquaViva payment still goes through.`,
    async run(c) {
      const m = await c.client.obtainMandate({ agentName: 'Bill assistant', person: 'luca', preset: UTIL });
      const payees = await c.client.callTool(m, 'list_payees', { category: 'utilities' });
      c.expect('list_payees', payees, 'ALLOW');
      // The fooled agent: it reads the note on the bill and does what it says.
      const hijack = /transfer to payee ([a-z0-9.-]+)/.exec(payees.text)?.[1];
      c.check('the tool result carries the injected instruction', hijack === ATTACKER_HOST, ATTACKER_HOST, hijack ?? 'none');
      await c.client.note('note', { text: `The agent read "pay ${hijack} instead" in the bill and tries it` });
      c.expect(`pay ${ATTACKER_HOST} 38.75 as instructed by the bill`, await c.client.callTool(m, 'transfer', { payee: hijack ?? ATTACKER_HOST, amount_cents: 3875, reference: 'AcquaViva Q3 2026' }), 'COUNTERPARTY_NOT_PERMITTED');
      c.expect('pay acquaviva.example 38.75', await c.client.callTool(m, 'transfer', { payee: 'acquaviva.example', amount_cents: 3875, reference: 'AcquaViva Q3 2026' }), 'ALLOW');
    },
  },
  {
    id: 'emandate',
    title: 'The same mandate as a TS12 e-mandate',
    expected: 'The platform asks for a urn:eudi:sca:emandate:1 e-mandate bound to the PID; the wallet shows the TS12 summary whose reference is the mandate hash; the bank accepts the root and enforces the limits as usual.',
    async run(c) {
      const m = await c.client.obtainMandate({ agentName: 'Bill assistant (e-mandate)', person: 'maria', preset: UTIL, emandate: true });
      const { chain } = (await (await fetch(`${c.urls.platform}/api/mandates/${m}`)).json()) as { chain: { root: { mandate?: unknown } } };
      c.check('the root carries the mandate next to the TS12 transaction data', chain.root.mandate !== undefined, 'root.mandate present', chain.root.mandate ? 'present' : 'absent');
      c.expect('pay TeleNord 29.90', await c.client.callTool(m, 'transfer', { payee: 'telenord.example', amount_cents: 2990, reference: 'TeleNord' }), 'ALLOW');
      c.expect('pay Lumen 180.00', await c.client.callTool(m, 'transfer', { payee: 'lumen-energia.example', amount_cents: 18000, reference: 'Lumen' }), 'LIMIT_PER_OPERATION');
    },
  },
  {
    id: 'per-operation-limit',
    title: 'Per-operation limit exceeded',
    expected: 'A 180 euro payment under a 150 euro per-operation limit is denied with LIMIT_PER_OPERATION.',
    async run(c) {
      const m = await c.client.obtainMandate({ agentName: 'Bill assistant', person: 'maria', preset: UTIL });
      c.expect('pay Lumen 180.00', await c.client.callTool(m, 'transfer', { payee: 'lumen-energia.example', amount_cents: 18000, reference: 'Lumen bill' }), 'LIMIT_PER_OPERATION');
    },
  },
  {
    id: 'total-limit',
    title: 'Total limit exceeded across several payments',
    expected: 'With 200 euro in total, 84.30 + 41.20 pass, a further 90.00 is denied with LIMIT_TOTAL, and the denial reserves nothing: 29.90 still passes.',
    async run(c) {
      const m = await c.client.obtainMandate({
        agentName: 'Bill assistant',
        person: 'maria',
        spec: {
          actions: ['payments.transfer'],
          counterparties: ['lumen-energia.example', 'acquaviva.example', 'telenord.example'],
          limits: { currency: 'EUR', per_operation: 15000, total: 20000 },
          ttlSeconds: 3600,
          purpose: 'Pay utility bills, 200 euro in total',
        },
      });
      c.expect('pay Lumen 84.30', await c.client.callTool(m, 'transfer', { payee: 'lumen-energia.example', amount_cents: 8430, reference: 'Lumen' }), 'ALLOW');
      c.expect('pay AcquaViva 41.20', await c.client.callTool(m, 'transfer', { payee: 'acquaviva.example', amount_cents: 4120, reference: 'AcquaViva' }), 'ALLOW');
      c.expect('pay TeleNord 90.00 (total would be 215.50)', await c.client.callTool(m, 'transfer', { payee: 'telenord.example', amount_cents: 9000, reference: 'TeleNord' }), 'LIMIT_TOTAL');
      c.expect('pay TeleNord 29.90 (total 155.40)', await c.client.callTool(m, 'transfer', { payee: 'telenord.example', amount_cents: 2990, reference: 'TeleNord' }), 'ALLOW');
    },
  },
  {
    id: 'payee-not-allowed',
    title: 'Payee not allowed by the mandate',
    expected: 'Rotaia is a registered payee at the bank but not in the utilities mandate: COUNTERPARTY_NOT_PERMITTED.',
    async run(c) {
      const m = await c.client.obtainMandate({ agentName: 'Bill assistant', person: 'maria', preset: UTIL });
      c.expect('pay Rotaia 45.00', await c.client.callTool(m, 'transfer', { payee: 'rotaia.example', amount_cents: 4500, reference: 'Roma-Milano' }), 'COUNTERPARTY_NOT_PERMITTED');
    },
  },
  {
    id: 'action-not-allowed',
    title: 'Action not allowed: blocking the card',
    expected: 'The mandate allows payments and reads only, so block_card is denied with ACTION_NOT_PERMITTED.',
    async run(c) {
      const m = await c.client.obtainMandate({ agentName: 'Bill assistant', person: 'maria', preset: UTIL });
      c.expect('block_card', await c.client.callTool(m, 'block_card', { reason: 'suspicious activity' }), 'ACTION_NOT_PERMITTED');
    },
  },
  {
    id: 'revocation',
    title: 'The person revokes the mandate mid-run',
    expected: 'After a first payment the person revokes the mandate at the platform; within the status cache time the bank denies with REVOKED.',
    async run(c) {
      const m = await c.client.obtainMandate({ agentName: 'Bill assistant', person: 'maria', preset: UTIL });
      c.expect('pay AcquaViva 41.20', await c.client.callTool(m, 'transfer', { payee: 'acquaviva.example', amount_cents: 4120, reference: 'AcquaViva' }), 'ALLOW');
      await c.client.setMandateState(m, 'revoke');
      const t0 = Date.now();
      const deadline = t0 + (c.statusCacheSeconds + 2) * 1000;
      let o: CallOutcome;
      do {
        o = await c.client.callTool(m, 'get_balance', {});
        if (o.decision === 'DENY') break;
        await c.sleep(250);
      } while (Date.now() < deadline);
      const ms = Date.now() - t0;
      c.check(`denied ${ms} ms after revocation (cache ${c.statusCacheSeconds} s)`, o.decision === 'DENY' && o.code === 'REVOKED', 'DENY REVOKED', describe(o));
      c.expect('pay TeleNord 29.90 after revocation', await c.client.callTool(m, 'transfer', { payee: 'telenord.example', amount_cents: 2990, reference: 'TeleNord' }), 'REVOKED');
    },
  },
  {
    id: 'sub-delegation',
    title: 'Sub-agent with a narrower mandate tries to exceed it',
    expected: 'The bill assistant delegates "AcquaViva only, 50 euro each, 60 total" to a sub-agent. The sub-agent pays AcquaViva, then is denied above its own limits, outside its payee and outside its actions; a wider delegation is refused at signing.',
    async run(c) {
      const parent = await c.client.obtainMandate({ agentName: 'Bill assistant', person: 'maria', preset: UTIL });
      const sub = await c.client.delegate(parent, 'Water-bill sub-agent', {
        actions: ['payments.transfer'],
        counterparties: ['acquaviva.example'],
        limits: { currency: 'EUR', per_operation: 5000, total: 6000 },
        ttlSeconds: 3600,
        purpose: 'Pay the AcquaViva water bill',
      });
      c.expect('sub-agent pays AcquaViva 41.20', await c.client.callTool(sub, 'transfer', { payee: 'acquaviva.example', amount_cents: 4120, reference: 'AcquaViva Q3' }), 'ALLOW');
      c.expect('sub-agent pays AcquaViva 55.00 (above its 50/op)', await c.client.callTool(sub, 'transfer', { payee: 'acquaviva.example', amount_cents: 5500, reference: 'AcquaViva' }), 'LIMIT_PER_OPERATION');
      c.expect('sub-agent pays AcquaViva 30.00 (its total would be 71.20)', await c.client.callTool(sub, 'transfer', { payee: 'acquaviva.example', amount_cents: 3000, reference: 'AcquaViva' }), 'LIMIT_TOTAL');
      c.expect('sub-agent pays Lumen 30.00 (not its payee)', await c.client.callTool(sub, 'transfer', { payee: 'lumen-energia.example', amount_cents: 3000, reference: 'Lumen' }), 'COUNTERPARTY_NOT_PERMITTED');
      c.expect('sub-agent reads the balance (not its action)', await c.client.callTool(sub, 'get_balance', {}), 'ACTION_NOT_PERMITTED');
      let refused = '';
      try {
        await c.client.delegate(parent, 'Greedy sub-agent', {
          actions: ['payments.transfer'],
          counterparties: ['acquaviva.example'],
          limits: { currency: 'EUR', per_operation: 5000, total: 50000 },
          ttlSeconds: 3600,
        });
      } catch (e) {
        refused = (e as Error).message;
      }
      c.check('a delegation wider than the parent is refused', /widens|total/.test(refused), 'refused (attenuation)', refused || 'accepted');
      c.expect('the parent agent still pays Lumen 84.30', await c.client.callTool(parent, 'transfer', { payee: 'lumen-energia.example', amount_cents: 8430, reference: 'Lumen' }), 'ALLOW');
    },
  },
  {
    id: 'replay',
    title: 'Replay of a captured invocation',
    expected: 'The same signed call sent twice: the first is allowed, the copy is denied with REPLAY and nothing is charged twice.',
    async run(c) {
      const m = await c.client.obtainMandate({ agentName: 'Bill assistant', person: 'maria', preset: UTIL });
      const call = await c.client.prepareCall(m, 'transfer', { payee: 'telenord.example', amount_cents: 2990, reference: 'TeleNord 2026-10' });
      c.expect('original call', await c.client.send(call), 'ALLOW');
      c.expect('captured copy sent again', await c.client.send(call), 'REPLAY');
    },
  },
  {
    id: 'concurrent',
    title: 'Two concurrent payments that together exceed the total',
    expected: 'With 100 euro in total, two 60 euro payments are sent at the same time: exactly one is allowed, the other is denied with LIMIT_TOTAL.',
    async run(c) {
      const m = await c.client.obtainMandate({
        agentName: 'Bill assistant',
        person: 'maria',
        spec: {
          actions: ['payments.transfer'],
          counterparties: ['lumen-energia.example', 'acquaviva.example'],
          limits: { currency: 'EUR', per_operation: 15000, total: 10000 },
          ttlSeconds: 3600,
          purpose: 'Utilities, 100 euro in total',
        },
      });
      const a = await c.client.prepareCall(m, 'transfer', { payee: 'lumen-energia.example', amount_cents: 6000, reference: 'Lumen' });
      const b = await c.client.prepareCall(m, 'transfer', { payee: 'acquaviva.example', amount_cents: 6000, reference: 'AcquaViva' });
      const [ra, rb] = await Promise.all([c.client.send(a), c.client.send(b)]);
      const outcomes = [ra, rb].map(describe).sort();
      c.check('exactly one of the two passes', outcomes[0] === 'ALLOW' && outcomes[1] === 'DENY LIMIT_TOTAL', 'ALLOW + DENY LIMIT_TOTAL', outcomes.join(' + '));
    },
  },
  {
    id: 'idempotent-retry',
    title: 'The answer to a payment is lost, and the agent retries',
    expected: 'The agent pays a bill but never sees the answer, so it sends the same call again with the same idempotency key. The bank returns the stored result of the first payment and pays nothing a second time; a new key is a new payment.',
    async run(c) {
      const m = await c.client.obtainMandate({ agentName: 'Bill assistant', person: 'maria', preset: UTIL });
      const before = await c.client.restBalance(m, c.audiences.rest);
      const key = newIdempotencyKey();
      const args = { payee: 'acquaviva.example', amount_cents: 4120, reference: 'AcquaViva bill Q3 2026' };
      const first = c.expect('pay AcquaViva 41.20 (the answer is lost on the way back)', await c.client.callTool(m, 'transfer', args, { idempotencyKey: key }), 'ALLOW');
      const retry = c.expect('the same call again, same key', await c.client.callTool(m, 'transfer', args, { idempotencyKey: key }), 'ALLOW');
      c.check('the retry is the stored answer of the first payment', retry.replay === true && retry.data?.transaction_id === first.data?.transaction_id, `replay of ${String(first.data?.transaction_id)}`, `${retry.replay ? 'replay' : 'new call'} ${String(retry.data?.transaction_id)}`);
      const after = await c.client.restBalance(m, c.audiences.rest);
      const diff = Number(before.body.balance_cents) - Number(after.body.balance_cents);
      c.check('paid once', diff === 4120, '4120 cents', `${diff} cents`);
      c.expect('the same key for a different amount', await c.client.callTool(m, 'transfer', { ...args, amount_cents: 4121 }, { idempotencyKey: key }), 'IDEMPOTENCY_CONFLICT');
    },
  },
  {
    id: 'retry-after-crash',
    title: 'The bank fails after the money left, and the agent retries',
    expected: 'Core banking times out after debiting the account. The retry with the same idempotency key is refused with IDEMPOTENCY_UNRESOLVED instead of paying again; once the bank reconciles the payment as executed, the retry is answered with ALREADY_EXECUTED. The account was debited once.',
    async run(c) {
      const m = await c.client.obtainMandate({ agentName: 'Bill assistant', person: 'luca', preset: UTIL });
      const before = await c.client.restBalance(m, c.audiences.rest);
      await c.admin(`${c.urls.bank}/admin/fail-next-transfer`);
      const key = newIdempotencyKey();
      const args = { payee: 'lumen-energia.example', amount_cents: 6230, reference: 'Lumen bill 2026-09' };
      const crashed = await c.client.callTool(m, 'transfer', args, { idempotencyKey: key });
      c.check('the bank does not answer: outcome unknown', crashed.decision === 'ALLOW' && crashed.isError && /did not answer in time/.test(crashed.text), 'ALLOW, then a timeout', describe(crashed));
      c.expect('retry with the same key', await c.client.callTool(m, 'transfer', args, { idempotencyKey: key }), 'IDEMPOTENCY_UNRESOLVED');
      const open = (await (await fetch(`${c.urls.bank}/api/idempotency`)).json()) as { unresolved: Array<{ key: string }> };
      c.check('the bank lists the payment for reconciliation', open.unresolved.length >= 1, 'at least one unresolved key', `${open.unresolved.length}`);
      // The bank finds the debit in its books and records it as executed.
      for (const r of open.unresolved) await c.admin(`${c.urls.bank}/admin/idempotency/${encodeURIComponent(r.key)}/resolve`, { outcome: 'executed' });
      c.expect('retry after the reconciliation', await c.client.callTool(m, 'transfer', args, { idempotencyKey: key }), 'ALREADY_EXECUTED');
      const after = await c.client.restBalance(m, c.audiences.rest);
      const diff = Number(before.body.balance_cents) - Number(after.body.balance_cents);
      c.check('debited once', diff === 6230, '6230 cents', `${diff} cents`);
    },
  },
  {
    id: 'expired',
    title: 'Expired mandate',
    expected: 'A one-hour mandate works now; with the bank clock one hour ahead the same agent is denied with EXPIRED.',
    async run(c) {
      const m = await c.client.obtainMandate({ agentName: 'Bill assistant', person: 'maria', preset: UTIL, ttlSeconds: 3600 });
      c.expect('pay TeleNord 29.90 now', await c.client.callTool(m, 'transfer', { payee: 'telenord.example', amount_cents: 2990, reference: 'TeleNord' }), 'ALLOW');
      await c.admin(`${c.urls.bank}/admin/clock`, { offset_seconds: 3601 });
      try {
        c.expect('pay AcquaViva 41.20 one hour later', await c.client.callTool(m, 'transfer', { payee: 'acquaviva.example', amount_cents: 4120, reference: 'AcquaViva' }), 'EXPIRED');
      } finally {
        await c.admin(`${c.urls.bank}/admin/clock`, { offset_seconds: 0 });
      }
    },
  },
  {
    id: 'pid-revoked',
    title: 'PID revoked at the provider',
    expected: "Luca's PID is revoked by the PID provider: the bank denies his agent with PID_REVOKED, and the platform refuses a new mandate from that PID. The PID is reinstated afterwards.",
    async run(c) {
      const m = await c.client.obtainMandate({ agentName: 'Bill assistant', person: 'luca', preset: UTIL });
      c.expect('pay Lumen 62.10', await c.client.callTool(m, 'transfer', { payee: 'lumen-energia.example', amount_cents: 6210, reference: 'Lumen' }), 'ALLOW');
      const persons = (await (await fetch(`${c.urls.wallet}/api/persons`)).json()) as Array<{ id: string; pid_id: string }>;
      const pidId = persons.find((p) => p.id === 'luca')!.pid_id;
      await c.admin(`${c.urls.pid}/admin/pids/${encodeURIComponent(pidId)}/revoke`);
      try {
        await c.sleep((c.statusCacheSeconds + 1) * 1000);
        c.expect('pay AcquaViva 38.75 after PID revocation', await c.client.callTool(m, 'transfer', { payee: 'acquaviva.example', amount_cents: 3875, reference: 'AcquaViva' }), 'PID_REVOKED');
        const req = await c.client.requestMandate({ agentName: 'Bill assistant', preset: UTIL });
        const clientId = new URL(req.authorization_url).searchParams.get('client_id')!;
        await c.client.walletDecide(req.request_uri, clientId, 'luca', 'approve');
        const s = await c.client.requestState(req.request_id);
        c.check('platform refuses a new mandate from the revoked PID', s.state === 'failed' && s.error === 'PID_REVOKED', 'failed PID_REVOKED', `${s.state} ${s.error ?? ''}`);
      } finally {
        await c.admin(`${c.urls.pid}/admin/pids/${encodeURIComponent(pidId)}/reinstate`);
        await c.sleep((c.statusCacheSeconds + 1) * 1000);
      }
    },
  },
  {
    id: 'tampered-mandate',
    title: 'The agent edits its own mandate to raise the limit',
    expected: 'The agent rewrites the transaction data in its chain to allow 1,500 euro per payment. The wallet signed the hash of the original bytes, so the bank denies with TX_DATA_MISMATCH.',
    async run(c) {
      const m = await c.client.obtainMandate({ agentName: 'Bill assistant', person: 'maria', preset: UTIL });
      const call = await c.client.prepareCall(m, 'transfer', { payee: 'lumen-energia.example', amount_cents: 120000, reference: 'Lumen' });
      const td = decodeMandateTransactionData(call.meta.chain.root.transaction_data);
      const forged = { ...td.mandate!, limits: { currency: 'EUR', per_operation: 150000, total: 300000 } };
      call.meta.chain.root.transaction_data = encodeMandateTransactionData(forged);
      c.expect('pay Lumen 1,200.00 with the forged mandate', await c.client.send(call), 'TX_DATA_MISMATCH');
    },
  },
  {
    id: 'wallet-refusal',
    title: 'The person refuses in the wallet',
    expected: 'The person taps Refuse: the platform records the refusal and no mandate exists for the agent to use.',
    async run(c) {
      const req = await c.client.requestMandate({ agentName: 'Pushy assistant', preset: UTIL });
      const clientId = new URL(req.authorization_url).searchParams.get('client_id')!;
      await c.client.walletDecide(req.request_uri, clientId, 'maria', 'refuse');
      const s = await c.client.requestState(req.request_id);
      c.check('request refused', s.state === 'refused' && s.error === 'access_denied', 'refused access_denied', `${s.state} ${s.error ?? ''}`);
      let signed = '';
      try {
        await c.client.sign(req.mandate_id, { action: 'payments.transfer', aud: c.audiences.mcp, args: {} });
        signed = 'signed';
      } catch (e) {
        signed = (e as Error).message;
      }
      c.check('the platform has no mandate to sign under', /404/.test(signed), 'HTTP 404 unknown mandate', signed);
    },
  },
  {
    id: 'double-approval',
    title: 'The person opens the approval link twice',
    expected: 'After an approval, reopening the link shows the request as approved, a second approval and any further response are refused with 409, the request object is gone (410), and the mandate stays active and usable.',
    async run(c) {
      const req = await c.client.requestMandate({ agentName: 'Bill assistant', preset: UTIL });
      const clientId = new URL(req.authorization_url).searchParams.get('client_id')!;
      const first = await c.client.walletDecide(req.request_uri, clientId, 'maria', 'approve');
      c.check('first approval accepted', first.state === 'approved', 'approved', first.state);
      const again = await c.client.walletOpen(req.request_uri, clientId, 'maria');
      c.check('reopening shows the request already approved', again.state === 'approved', 'approved', again.state);
      let second = '';
      try {
        await c.client.walletDecideById(again.id, 'maria', 'approve');
        second = 'accepted';
      } catch (e) {
        second = (e as Error).message;
      }
      c.check('a second approval is refused by the wallet', /409/.test(second), 'HTTP 409', second);
      const refetch = await fetch(req.request_uri);
      c.check('the request object is no longer served', refetch.status === 410, 'HTTP 410', `HTTP ${refetch.status}`);
      const extra = await fetch(req.request_uri.replace('/request/', '/response/'), {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ vp_token: '{}', state: 'x' }).toString(),
      });
      c.check('a late response is refused without effect', extra.status === 409, 'HTTP 409', `HTTP ${extra.status}`);
      const s = await c.client.requestState(req.request_id);
      c.check('the request is still active', s.state === 'active' && !s.error, 'active', `${s.state} ${s.error ?? ''}`.trim());
      c.expect('pay Lumen 84.30', await c.client.callTool(s.mandate_id, 'transfer', { payee: 'lumen-energia.example', amount_cents: 8430, reference: 'Lumen bill 2026-10' }), 'ALLOW');
    },
  },
];

export async function runScenario(s: Scenario, env: ScenarioEnv): Promise<ScenarioResult> {
  const steps: Step[] = [];
  const t0 = Date.now();
  const ctx: Ctx = {
    ...env,
    expect(label, o, expected) {
      const actual = describe(o);
      const ok = expected === 'ALLOW' ? actual === 'ALLOW' : actual === `DENY ${expected}`;
      steps.push({ label, expected: expected === 'ALLOW' ? 'ALLOW' : `DENY ${expected}`, actual: actual + (o.decision === 'ALLOW' || ok ? '' : ` (${o.text})`), ok });
      return o;
    },
    check(label, ok, expected, actual) {
      steps.push({ label, expected, actual, ok });
    },
    sleep: (ms) => new Promise((r) => setTimeout(r, ms)),
    async admin(url, body = {}) {
      const res = await fetch(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...(env.adminToken ? { authorization: `Bearer ${env.adminToken}` } : {}) },
        body: JSON.stringify(body),
      });
      if (!res.ok) throw new Error(`admin call ${url} failed: HTTP ${res.status}`);
      return res;
    },
  };
  await env.client.note('scenario_start', { id: s.id, title: s.title, expected: s.expected });
  let error: string | undefined;
  try {
    await s.run(ctx);
  } catch (e) {
    error = (e as Error).message;
  }
  const pass = !error && steps.length > 0 && steps.every((x) => x.ok);
  const failed = steps.filter((x) => !x.ok).map((x) => `${x.label}: got ${x.actual}`);
  await env.client.note('scenario_result', {
    id: s.id,
    title: s.title,
    pass,
    observed: error ?? (failed.length ? failed.join('; ') : `${steps.length} checks`),
  });
  return { id: s.id, title: s.title, expected: s.expected, pass, steps, error, ms: Date.now() - t0 };
}

export function formatResult(r: ScenarioResult, color = true): string {
  const g = (s: string) => (color ? `\x1b[32m${s}\x1b[0m` : s);
  const red = (s: string) => (color ? `\x1b[31m${s}\x1b[0m` : s);
  const dim = (s: string) => (color ? `\x1b[2m${s}\x1b[0m` : s);
  const lines = [`${r.pass ? g('PASS') : red('FAIL')}  ${r.title} ${dim(`(${r.id}, ${r.ms} ms)`)}`, dim(`      expected: ${r.expected}`)];
  for (const s of r.steps) lines.push(`      ${s.ok ? g('✓') : red('✗')} ${s.label}: ${s.actual}${s.ok ? '' : ` ${dim(`(expected ${s.expected})`)}`}`);
  if (r.error) lines.push(red(`      error: ${r.error}`));
  return lines.join('\n');
}
