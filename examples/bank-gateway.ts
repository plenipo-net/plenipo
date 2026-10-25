/**
 * A bank puts the Plenipo gateway in front of its payments API. An agent with a bills mandate pays a
 * listed payee, then tries a payee outside the mandate and an amount above the limit, and reads the
 * balance with a route that moves no money.
 *
 *   npm run example:gateway
 *
 * Everything runs in one process with test keys: a test PID provider and wallet stand in for the EUDI
 * ones. With PLENIPO_PG_URL set, nonces and spending totals live in Postgres instead of memory.
 */
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import {
  authorizationHeaders,
  createGateway,
  createInvocation,
  createMandate,
  generateAgentKey,
  InMemoryNonceStore,
  InMemorySpendingLedger,
  toNodeListener,
  type MandateChain,
  type NonceStore,
  type SpendingLedger,
} from '../src/index.js';
import { createTestPidProvider, createTestWallet } from '../src/testing.js';

const API = 'https://api.bank.example';

// 1. Test identity: a PID provider and the person's wallet.
const pidProvider = await createTestPidProvider('https://pid.example.eu');
const wallet = await createTestWallet();
wallet.storePid(await pidProvider.issuePid(wallet.holderJwk, { given_name: 'Maria', family_name: 'Rossi' }));

// 2. The agent asks for a mandate and Maria approves it in her wallet.
const agent = await generateAgentKey();
const mandate = createMandate({
  agentJwk: agent.publicJwk,
  actions: ['payments.transfer', 'accounts.read'],
  counterparties: ['acquaviva.example', 'lumen-energia.example'],
  limits: { currency: 'EUR', per_operation: 15000, total: 30000 },
  ttlSeconds: 30 * 86400,
  purpose: 'Pay the household bills',
});
const chain: MandateChain = { root: await wallet.approveMandate(mandate), delegations: [] };

// 3. The bank: stores, gateway, and the API behind it.
let nonces: NonceStore = new InMemoryNonceStore();
let ledger: SpendingLedger = new InMemorySpendingLedger();
if (process.env.PLENIPO_PG_URL) {
  const pg = await import('pg');
  const { PostgresNonceStore, PostgresSpendingLedger, migratePostgres } = await import('../src/index.js');
  const pool = new pg.default.Pool({ connectionString: process.env.PLENIPO_PG_URL });
  await migratePostgres(pool);
  nonces = new PostgresNonceStore(pool);
  ledger = new PostgresSpendingLedger(pool);
}

const gateway = createGateway({
  routes: [
    {
      method: 'POST',
      path: '/accounts/:account/payments',
      action: 'payments.transfer',
      counterparty: (r) => (r.json() as { payee_host: string }).payee_host,
      amount: (r) => {
        const b = r.json() as { amount_minor: number; currency: string };
        return { value: b.amount_minor, currency: b.currency };
      },
    },
    { method: 'GET', path: '/accounts/:account/balance', action: 'accounts.read', counterparty: null, amount: null },
  ],
  verify: { audience: API, nonces, ledger, trustedIssuers: [pidProvider.trusted] },
  downstream: async (request, ctx) => {
    if (request.method === 'GET') return Response.json({ account: ctx?.params.account, balance_minor: 123456, currency: 'EUR' });
    const body = (await request.json()) as { payee_host: string; amount_minor: number };
    return Response.json({ status: 'executed', payee: body.payee_host, amount_minor: body.amount_minor });
  },
});

const server = http.createServer({ maxHeaderSize: 80 * 1024 }, toNodeListener(gateway.handle, { origin: API }));
await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

// 4. The agent calls the API. Each call carries the chain and an invocation bound to the exact request.
async function pay(payee_host: string, amount_minor: number) {
  const path = '/accounts/acc-1/payments';
  const body = { payee_host, amount_minor, currency: 'EUR', iban: 'IT60X0542811101000000123456' };
  const invocation = await createInvocation(agent.privateKey, {
    chain,
    mandateId: mandate.id,
    action: 'payments.transfer',
    counterparty: payee_host,
    amount: { value: amount_minor, currency: 'EUR' },
    aud: API,
    args: { method: 'POST', path, query: {}, media_type: 'application/json', body },
  });
  const res = await fetch(base + path, {
    method: 'POST',
    headers: { ...authorizationHeaders(chain, invocation), 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
  await report(`pay ${payee_host} ${(amount_minor / 100).toFixed(2)} EUR`, res);
}

async function balance() {
  const path = '/accounts/acc-1/balance';
  const invocation = await createInvocation(agent.privateKey, {
    chain,
    mandateId: mandate.id,
    action: 'accounts.read',
    aud: API,
    args: { method: 'GET', path, query: {}, media_type: null, body: null },
  });
  await report('read balance', await fetch(base + path, { headers: authorizationHeaders(chain, invocation) }));
}

async function report(what: string, res: Response) {
  const text = await res.text();
  console.log(`${what.padEnd(36)} ${res.status} ${text}`);
}

await pay('acquaviva.example', 8950);
await pay('example.org', 1000);
await pay('lumen-energia.example', 20000);
await balance();

server.close();
process.exit(0);
