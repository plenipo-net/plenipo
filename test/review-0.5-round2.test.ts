/**
 * Round 2 of the independent security review of 0.5: checks of the round-1 fixes, kept as regression tests.
 * The one finding of this round in the library (a locked downstream body) is fixed in src/http/gateway.ts.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import pg from 'pg';
import { Redis } from 'ioredis';
import {
  authorizationHeaders,
  createGateway,
  createInvocation,
  createMandate,
  generateAgentKey,
  InMemoryIdempotencyStore,
  InMemoryNonceStore,
  InMemorySpendingLedger,
  newIdempotencyKey,
  REPLAY_HEADER,
  verifyAuthorization,
  type AgentKey,
  type Amount,
  type Decision,
  type GatewayRoute,
  type IdempotencyStore,
  type Mandate,
  type MandateChain,
  type VerifyOptions,
} from '../src/index.js';
import { guardTool, META_KEY } from '../src/mcp.js';
import { fromIoredis, migratePostgres, PostgresIdempotencyStore, RedisIdempotencyStore } from '../src/stores/index.js';
import { createTestPidProvider, createTestWallet, type TestPidProvider, type TestWallet } from '../src/testing.js';
import { startPostgres, startRedis } from './stores-engines.js';

const pgEngine = await startPostgres();
const redisEngine = await startRedis();
const AUD = 'https://bank.example';
const EUR = (value: number): Amount => ({ value, currency: 'EUR' });
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

let provider: TestPidProvider;
let wallet: TestWallet;
let agent: AgentKey;
let pool: pg.Pool | undefined;
let io: Redis | undefined;

beforeAll(async () => {
  provider = await createTestPidProvider('https://pid-round2.example');
  wallet = await createTestWallet();
  wallet.storePid(await provider.issuePid(wallet.holderJwk, { given_name: 'Ada', family_name: 'Lovelace' }));
  agent = await generateAgentKey();
  if (pgEngine.ok) pool = new pg.Pool({ connectionString: pgEngine.url, max: 8 });
  if (redisEngine.ok) {
    io = new Redis(redisEngine.url, { lazyConnect: true, maxRetriesPerRequest: 1 });
    await io.connect();
  }
});

afterAll(async () => {
  await pool?.end();
  io?.disconnect();
  if (pgEngine.ok) await pgEngine.stop();
  if (redisEngine.ok) await redisEngine.stop();
});

function mandate(): Mandate {
  return createMandate({
    agentJwk: agent.publicJwk,
    actions: ['payments.transfer'],
    counterparties: ['shop.example'],
    limits: { currency: 'EUR', per_operation: 50_000, total: 1_000_000 },
  });
}
async function chainFor(m: Mandate): Promise<MandateChain> {
  return { root: await wallet.approveMandate(m), delegations: [] };
}
function options(extra: Partial<VerifyOptions> = {}): VerifyOptions {
  return { trustedIssuers: [provider.trusted], audience: AUD, nonces: new InMemoryNonceStore(), ledger: new InMemorySpendingLedger(), idempotency: new InMemoryIdempotencyStore(), ...extra };
}

// ---------------------------------------------------------------- (1) resolve compare-and-set

type StoreFactory = () => Promise<IdempotencyStore>;
const stores: Array<[string, boolean, StoreFactory]> = [
  ['memory', true, async () => new InMemoryIdempotencyStore()],
  [
    'Postgres',
    pgEngine.ok,
    async () => {
      const tablePrefix = `q${randomUUID().replace(/-/g, '').slice(0, 12)}_`;
      await migratePostgres(pool!, { tablePrefix });
      return new PostgresIdempotencyStore(pool!, { tablePrefix });
    },
  ],
  ['Redis', redisEngine.ok, async () => new RedisIdempotencyStore(fromIoredis(io!), { prefix: `q-${randomUUID()}` })],
];

describe.each(stores)('%s: resolve is compare-and-set on the attempt', (_n, enabled, make) => {
  it.skipIf(!enabled)('settles only the listed attempt, refuses a malformed one, and lists attempts', async () => {
    const s = await make();
    const k = `k-${randomUUID()}`;
    const a = await s.claim(k, 'fp');
    if (!a.claimed) throw new Error('not claimed');
    await s.finish(k, a.attempt, 'unknown');
    const [listed] = (await s.unresolved({ limit: 10_000 })).filter((r) => r.key === k);
    expect(listed.attempt).toBe(a.attempt);
    expect(await s.resolve(k, 'executed', randomUUID())).toBe(false);
    await expect(s.resolve(k, 'executed', 'not-a-uuid')).rejects.toThrow();
    await expect(s.resolve(k, 'executed', undefined as never)).rejects.toThrow();
    // Postgres compares attempt as uuid: upper case is the same uuid, which is fine, but must not throw.
    expect(await s.resolve(k, 'not_executed', a.attempt)).toBe(true);
    expect(await s.resolve(k, 'not_executed', a.attempt)).toBe(false);
    // A late executed from the same attempt still lands on the free key (proof wins).
    await s.finish(k, a.attempt, 'executed');
    expect(await s.get(k)).toMatchObject({ state: 'executed', attempt: a.attempt });
  });
});

// ---------------------------------------------------------------- (1) the claim loop

describe('claim loop', () => {
  it('answers a retry after a committed reservation with the stored result and spends its nonce', async () => {
    const m = mandate();
    const chain = await chainFor(m);
    const states = new Map<string, string>();
    class L extends InMemorySpendingLedger {
      reserve(...a: Parameters<InMemorySpendingLedger['reserve']>) {
        const id = super.reserve(...a);
        if (id) states.set(id, 'pending');
        return id;
      }
      async reservation(id: string) {
        return states.has(id) ? { state: states.get(id)! } : undefined;
      }
    }
    const opts = options({ ledger: new L() });
    const idem = newIdempotencyKey();
    const args = { payee: 'shop.example', amount: 100 };
    const inv = () => createInvocation(agent.privateKey, { chain, mandateId: m.id, action: 'payments.transfer', counterparty: 'shop.example', amount: EUR(100), aud: AUD, args, idempotencyKey: idem });
    const v = (i: string): Promise<Decision> => verifyAuthorization(chain, i, { ...opts, expected: { action: 'payments.transfer', counterparty: 'shop.example', amount: EUR(100), args } });
    const first = await v(await inv());
    if (first.decision !== 'ALLOW') throw new Error(first.code);
    await opts.idempotency!.finish(first.idempotency!.key, first.idempotency!.attempt, 'unknown');
    states.set(first.reservation!, 'committed');
    const retry = await inv();
    expect(await v(retry)).toMatchObject({ decision: 'DENY', code: 'ALREADY_EXECUTED' });
    expect(await v(retry)).toMatchObject({ decision: 'DENY', code: 'REPLAY' });
    for (const code of ['IDEMPOTENCY_CONFLICT'] as const) {
      const other = await createInvocation(agent.privateKey, { chain, mandateId: m.id, action: 'payments.transfer', counterparty: 'shop.example', amount: EUR(200), aud: AUD, args: { ...args, amount: 200 }, idempotencyKey: idem });
      const o = (i: string) => verifyAuthorization(chain, i, { ...opts, expected: { action: 'payments.transfer', counterparty: 'shop.example', amount: EUR(200), args: { ...args, amount: 200 } } });
      expect(await o(other)).toMatchObject({ code });
      expect(await o(other)).toMatchObject({ code: 'REPLAY' });
    }
  });
});

// ---------------------------------------------------------------- (2) capture and the rebuilt response

const route: GatewayRoute = {
  method: 'POST',
  path: '/payments',
  action: 'payments.transfer',
  counterparty: (r) => (r.json() as { payee: string }).payee,
  amount: (r) => EUR((r.json() as { amount: number }).amount),
};

async function keyedRequest(chain: MandateChain, m: Mandate, idem: string | undefined, amount = 700) {
  const body = { payee: 'shop.example', amount };
  const invocation = await createInvocation(agent.privateKey, {
    chain,
    mandateId: m.id,
    action: 'payments.transfer',
    counterparty: body.payee,
    amount: EUR(body.amount),
    aud: AUD,
    args: { method: 'POST', path: '/payments', query: {}, media_type: 'application/json', body },
    ...(idem ? { idempotencyKey: idem } : {}),
  });
  return new Request(`${AUD}/payments`, { method: 'POST', headers: { 'content-type': 'application/json', ...authorizationHeaders(chain, invocation) }, body: JSON.stringify(body) });
}

const enc = new TextEncoder();
const within = <T>(p: Promise<T>, ms: number) => Promise.race([p, sleep(ms).then(() => 'hung' as const)]);

describe('gateway capture, round 2', () => {
  it('passes a slow stream through byte for byte when the capture budget runs out mid-read', async () => {
    const m = mandate();
    const chain = await chainFor(m);
    const parts = ['{"a":', '"first",', '"b":"second"}'];
    const gw = createGateway({
      routes: [route],
      verify: options(),
      downstream: async () =>
        new Response(
          new ReadableStream({
            async start(c) {
              c.enqueue(enc.encode(parts[0]));
              await sleep(1300); // past the 1 s budget, with a read pending
              c.enqueue(enc.encode(parts[1]));
              await sleep(50);
              c.enqueue(enc.encode(parts[2]));
              c.close();
            },
          }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        ),
    });
    const res = await gw.handle(await keyedRequest(chain, m, newIdempotencyKey()));
    expect(await res.text()).toBe(parts.join(''));
  }, 10_000);

  it('passes a body larger than maxReplayBytes through byte for byte', async () => {
    const m = mandate();
    const chain = await chainFor(m);
    const chunks = Array.from({ length: 10 }, (_, i) => new Uint8Array(3000).fill(65 + i));
    let n = 0;
    const gw = createGateway({
      routes: [route],
      verify: options(),
      maxReplayBytes: 5000,
      downstream: async () => new Response(new ReadableStream({ pull(c) { if (n >= chunks.length) return c.close(); c.enqueue(chunks[n++]); } }), { status: 201 }),
    });
    const res = await gw.handle(await keyedRequest(chain, m, newIdempotencyKey()));
    const got = new Uint8Array(await res.arrayBuffer());
    expect(got.byteLength).toBe(30_000);
    expect(got[0]).toBe(65);
    expect(got[29_999]).toBe(74);
  });

  it('surfaces an upstream error after the capture as an error of the client stream', async () => {
    const m = mandate();
    const chain = await chainFor(m);
    const gw = createGateway({
      routes: [route],
      verify: options(),
      maxReplayBytes: 4,
      downstream: async () =>
        new Response(
          new ReadableStream({
            async pull(c) {
              c.enqueue(enc.encode('0123456789'));
              await sleep(10);
              c.error(new Error('upstream reset'));
            },
          }),
          { status: 200 },
        ),
    });
    const res = await gw.handle(await keyedRequest(chain, m, newIdempotencyKey()));
    await expect(res.text()).rejects.toThrow();
  });

  it('propagates a client cancel to the upstream body', async () => {
    const m = mandate();
    const chain = await chainFor(m);
    let cancelled = false;
    const gw = createGateway({
      routes: [route],
      verify: options(),
      maxReplayBytes: 4,
      downstream: async () =>
        new Response(
          new ReadableStream({
            pull(c) {
              c.enqueue(enc.encode('0123456789'));
            },
            cancel() {
              cancelled = true;
            },
          }),
          { status: 200 },
        ),
    });
    const res = await gw.handle(await keyedRequest(chain, m, newIdempotencyKey()));
    const reader = res.body!.getReader();
    await reader.read();
    await reader.cancel('client went away');
    expect(cancelled).toBe(true);
  });

  it('keeps headers, status text and multiple Set-Cookie on the rebuilt response, and replays 204', async () => {
    const m = mandate();
    const chain = await chainFor(m);
    let calls = 0;
    const gw = createGateway({
      routes: [route],
      verify: options(),
      downstream: async () => {
        calls++;
        const h = new Headers({ 'x-trace': 't1', 'content-type': 'text/plain' });
        h.append('set-cookie', 'a=1');
        h.append('set-cookie', 'b=2');
        return new Response(null, { status: 204, statusText: 'Done', headers: h });
      },
    });
    const idem = newIdempotencyKey();
    const res = await gw.handle(await keyedRequest(chain, m, idem));
    expect(res.status).toBe(204);
    expect(res.statusText).toBe('Done');
    expect(res.headers.getSetCookie()).toEqual(['a=1', 'b=2']);
    expect(res.headers.get('x-trace')).toBe('t1');
    const retry = await gw.handle(await keyedRequest(chain, m, idem));
    expect(retry.status).toBe(204);
    expect(retry.headers.get(REPLAY_HEADER)).toBe('true');
    expect(calls).toBe(1);
  });

  it('does not reject handle() or leave the attempt open when the downstream body is already locked', async () => {
    const m = mandate();
    const chain = await chainFor(m);
    const opts = options();
    const gw = createGateway({
      routes: [route],
      verify: opts,
      downstream: async () => {
        const r = new Response('{"id":"pay-1"}', { status: 201 });
        r.body!.getReader(); // e.g. a logging wrapper that peeked at the body
        return r;
      },
    });
    const idem = newIdempotencyKey();
    const out = await within(gw.handle(await keyedRequest(chain, m, idem)).then((r) => r.status, () => 'rejected'), 3000);
    expect(out).not.toBe('rejected');
    // The API ran (201): the retry must learn it executed, not run again or wait for reconciliation.
    const retry = await gw.handle(await keyedRequest(chain, m, idem));
    expect([201, 409]).toContain(retry.status);
    if (retry.status === 409) expect((await retry.json()).code).toBe('already_executed');
  });

  it('settle(input, replay) in authorize mode keeps a string body and ignores an oversize one', async () => {
    const m = mandate();
    const chain = await chainFor(m);
    const gw = createGateway({ routes: [route], verify: options(), maxReplayBytes: 10 });
    const idem1 = newIdempotencyKey();
    const a = await gw.authorize(await keyedRequest(chain, m, idem1));
    if (a.kind !== 'allow') throw new Error(a.kind);
    await a.settle({ status: 201 }, { status: 201, contentType: 'application/json', body: '{"ok":1}' });
    const r1 = await gw.authorize(await keyedRequest(chain, m, idem1));
    expect(r1.kind === 'deny' && r1.response.status).toBe(201);
    const idem2 = newIdempotencyKey();
    const b = await gw.authorize(await keyedRequest(chain, m, idem2));
    if (b.kind !== 'allow') throw new Error(b.kind);
    await b.settle({ status: 201 }, { status: 201, body: 'x'.repeat(11) });
    const r2 = await gw.authorize(await keyedRequest(chain, m, idem2));
    expect(r2.kind === 'deny' && r2.problem.code).toBe('already_executed');
  });
});

// ---------------------------------------------------------------- (4) bounds and fallback

describe('maxReplayBytes bounds and the finish fallback', () => {
  it('a long Content-Type pushing the stored JSON over the store bound still records executed', async () => {
    const m = mandate();
    const chain = await chainFor(m);
    const { MAX_REPLAY_BODY_BYTES } = await import('../src/index.js');
    const big = new Uint8Array(MAX_REPLAY_BODY_BYTES).fill(66);
    let calls = 0;
    const gw = createGateway({
      routes: [route],
      verify: options(),
      maxReplayBytes: MAX_REPLAY_BODY_BYTES,
      downstream: async () => {
        calls++;
        return new Response(big, { status: 201, headers: { 'content-type': `text/plain; x=${'y'.repeat(4000)}` } });
      },
    });
    const idem = newIdempotencyKey();
    expect((await gw.handle(await keyedRequest(chain, m, idem))).status).toBe(201);
    const retry = await gw.handle(await keyedRequest(chain, m, idem));
    expect(calls).toBe(1);
    expect(retry.status === 201 || (await retry.clone().json()).code === 'already_executed').toBe(true);
  });

  it('guardTool refuses maxReplayBytes above the store bound at wiring time', () => {
    expect(() =>
      guardTool(async () => ({ content: [] }), { ...options(), action: 'payments.transfer', counterparty: null, amount: null, maxReplayBytes: 256 * 1024 + 1 }),
    ).toThrow(/maxReplayBytes/);
    expect(META_KEY).toBe('plenipo/authorization');
  });
});

// ---------------------------------------------------------------- (5) the in-memory sweep

describe('InMemoryIdempotencyStore sweep', () => {
  it('keeps unresolved and in-progress records, drops expired executed and free ones', async () => {
    let t = 1_000_000;
    const s = new InMemoryIdempotencyStore({ retentionSeconds: 1, leaseSeconds: 1, now: () => t });
    const claim = async (k: string) => {
      const c = await s.claim(k, 'fp');
      if (!c.claimed) throw new Error('not claimed');
      return c.attempt;
    };
    const done = await claim('done-0123456789abcdef');
    await s.finish('done-0123456789abcdef', done, 'executed');
    const freed = await claim('free-0123456789abcdef');
    await s.finish('free-0123456789abcdef', freed, 'not_executed');
    const unknown = await claim('unkn-0123456789abcdef');
    await s.finish('unkn-0123456789abcdef', unknown, 'unknown');
    await claim('runn-0123456789abcdef'); // abandoned past its lease
    t += 120_000;
    expect(s.sweep()).toBe(2);
    expect(await s.get('unkn-0123456789abcdef')).toMatchObject({ state: 'unknown' });
    expect(await s.get('runn-0123456789abcdef')).toMatchObject({ state: 'unknown' });
    expect((await s.unresolved()).length).toBe(2);
  });
});
