/**
 * Regression tests from the independent security review of 0.5 (idempotency keys, status age). Each one
 * reproduced a finding before its fix. The bridge findings are tested in sandbox/test/bridge-retry.e2e.ts;
 * that two tools sharing an action and arguments share a key's result is documented (docs/integration.md).
 */
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import pg from 'pg';
import {
  authorizationHeaders,
  createGateway,
  createInvocation,
  createMandate,
  generateAgentKey,
  InMemoryIdempotencyStore,
  MAX_REPLAY_BODY_BYTES,
  MAX_STORED_RESULT_BYTES,
  InMemoryNonceStore,
  InMemorySpendingLedger,
  newIdempotencyKey,
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
import { Redis } from 'ioredis';
import { createTestPidProvider, createTestWallet, type TestPidProvider, type TestWallet } from '../src/testing.js';
import { startPostgres, startRedis } from './stores-engines.js';

const pgEngine = await startPostgres();
const redisEngine = await startRedis();
let io: Redis | undefined;
const AUD = 'https://bank.example';
const EUR = (value: number): Amount => ({ value, currency: 'EUR' });

let provider: TestPidProvider;
let wallet: TestWallet;
let agent: AgentKey;
let pool: pg.Pool | undefined;

beforeAll(async () => {
  provider = await createTestPidProvider('https://pid-review.example');
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

function mandate(overrides: Partial<Parameters<typeof createMandate>[0]> = {}): Mandate {
  return createMandate({
    agentJwk: agent.publicJwk,
    actions: ['payments.transfer', 'accounts.read'],
    counterparties: ['shop.example', 'other.example'],
    limits: { currency: 'EUR', per_operation: 50_000, total: 1_000_000 },
    ...overrides,
  });
}

async function chainFor(m: Mandate): Promise<MandateChain> {
  return { root: await wallet.approveMandate(m), delegations: [] };
}

function options(extra: Partial<VerifyOptions> = {}): VerifyOptions {
  return {
    trustedIssuers: [provider.trusted],
    audience: AUD,
    nonces: new InMemoryNonceStore(),
    ledger: new InMemorySpendingLedger(),
    idempotency: new InMemoryIdempotencyStore(),
    ...extra,
  };
}

const args = (value: number) => ({ payee: 'shop.example', amount: value });

function pay(chain: MandateChain, m: Mandate, value: number, idem: string): Promise<string> {
  return createInvocation(agent.privateKey, {
    chain,
    mandateId: m.id,
    action: 'payments.transfer',
    counterparty: 'shop.example',
    amount: EUR(value),
    aud: AUD,
    args: args(value),
    idempotencyKey: idem,
  });
}

function verify(chain: MandateChain, inv: string, opts: VerifyOptions, value: number): Promise<Decision> {
  return verifyAuthorization(chain, inv, { ...opts, expected: { action: 'payments.transfer', counterparty: 'shop.example', amount: EUR(value), args: args(value) } });
}

/**
 * A ledger that can say what became of a reservation (like the Postgres and Redis ledgers), with a gate
 * that holds the next lookup until released, to interleave two retries deterministically.
 */
class GatedLedger extends InMemorySpendingLedger {
  readonly states = new Map<string, string>();
  private gate?: { opened: Promise<void>; entered: () => void };
  armed?: Promise<void>;
  private open: () => void = () => undefined;
  reserve(...a: Parameters<InMemorySpendingLedger['reserve']>) {
    const id = super.reserve(...a);
    if (id) this.states.set(id, 'pending');
    return id;
  }
  /** The next lookup waits until `release()`; `armed` resolves once a lookup is waiting. */
  holdNextLookup(): void {
    let entered!: () => void;
    this.armed = new Promise<void>((r) => (entered = r));
    const opened = new Promise<void>((r) => (this.open = r));
    this.gate = { opened, entered };
  }
  release(): void;
  release(id: string): void;
  release(id?: string): void {
    if (id === undefined) {
      this.open();
      return;
    }
    super.release(id);
  }
  async reservation(id: string) {
    const g = this.gate;
    if (g) {
      this.gate = undefined;
      g.entered();
      await g.opened;
    }
    return this.states.has(id) ? { state: this.states.get(id)! } : undefined;
  }
}

type StoreFactory = () => Promise<IdempotencyStore>;
const stores: Array<[string, boolean, StoreFactory]> = [
  ['memory', true, async () => new InMemoryIdempotencyStore()],
  [
    'Postgres',
    pgEngine.ok,
    async () => {
      const tablePrefix = `r${randomUUID().replace(/-/g, '').slice(0, 12)}_`;
      await migratePostgres(pool!, { tablePrefix });
      return new PostgresIdempotencyStore(pool!, { tablePrefix });
    },
  ],
  ['Redis', redisEngine.ok, async () => new RedisIdempotencyStore(fromIoredis(io!), { prefix: `r-${randomUUID()}` })],
];

// ---------------------------------------------------------------- finding 1: resolve is not tied to an attempt

describe.each(stores)('%s: ledger-follow of a released reservation', (_name, enabled, make) => {
  it.skipIf(!enabled)('never lets two concurrent retries of one intention both reach the action', async () => {
    const m = mandate();
    const chain = await chainFor(m);
    const ledger = new GatedLedger();
    const opts = options({ ledger, idempotency: await make() });
    const idem = newIdempotencyKey();

    // Attempt A: allowed, then its outcome is unknown (host crash, 5xx...).
    const a = await verify(chain, await pay(chain, m, 1_000, idem), opts, 1_000);
    if (a.decision !== 'ALLOW') throw new Error(`A: ${a.code}`);
    await opts.idempotency!.finish(a.idempotency!.key, a.idempotency!.attempt, 'unknown');
    // The bank reconciles A's reservation: it did not run. The key may now be retried once.
    ledger.states.set(a.reservation!, 'released');

    // Two retries of the same intention (two host instances, or a timer and a user click).
    ledger.holdNextLookup();
    const b2 = verify(chain, await pay(chain, m, 1_000, idem), opts, 1_000); // reads A's record, waits on the ledger
    await ledger.armed;
    const b1 = await verify(chain, await pay(chain, m, 1_000, idem), opts, 1_000); // frees the key, claims it, ALLOW
    expect(b1.decision).toBe('ALLOW');
    ledger.release(); // b2 now learns "released" and calls resolve(key, 'not_executed') on b1's live attempt
    const second = await b2;
    // Expected: IDEMPOTENCY_IN_PROGRESS. A second ALLOW means the action runs twice for one key.
    expect(second).toMatchObject({ decision: 'DENY', code: 'IDEMPOTENCY_IN_PROGRESS' });
  });

  it.skipIf(!enabled)('an operator resolve based on a stale listing does not free a newer live attempt', async () => {
    const store = await make();
    const k = `k-${randomUUID()}`;
    const first = await store.claim(k, 'fp');
    if (!first.claimed) throw new Error('not claimed');
    await store.finish(k, first.attempt, 'unknown');
    const [listed] = (await store.unresolved({ limit: 10_000 })).filter((r) => r.key === k);
    expect(listed.attempt).toBe(first.attempt);
    // Meanwhile the key is freed (ledger follow) and a new attempt takes it and is running.
    await store.resolve(k, 'not_executed', first.attempt);
    const second = await store.claim(k, 'fp');
    if (!second.claimed) throw new Error('not claimed');
    // The operator acts on the listing: "the attempt I looked at did not run".
    expect(await store.resolve(listed.key, 'not_executed', listed.attempt)).toBe(false);
    // Expected: the running attempt still holds the key; otherwise a third attempt can claim it.
    expect(await store.claim(k, 'fp')).toMatchObject({ claimed: false, record: { state: 'in_progress', attempt: second.attempt } });
  });
});

// ---------------------------------------------------------------- finding 3: results above the store bound

describe('gateway: a kept response larger than the store accepts', () => {
  it('still lets the retry learn that the request executed', async () => {
    const m = mandate();
    const chain = await chainFor(m);
    const route: GatewayRoute = {
      method: 'POST',
      path: '/payments',
      action: 'payments.transfer',
      counterparty: (r) => (r.json() as { payee: string }).payee,
      amount: (r) => EUR((r.json() as { amount: number }).amount),
    };
    const downstream = vi.fn(async () => new Response('x'.repeat(200_000), { status: 201, headers: { 'content-type': 'text/plain' } }));
    // A bound the store cannot hold once encoded is refused when the gateway is built...
    expect(() => createGateway({ routes: [route], verify: options(), downstream, maxReplayBytes: 256 * 1024 })).toThrow(/maxReplayBytes/);
    // ...and at the largest allowed bound, a body above it is passed through and not kept.
    const gw = createGateway({ routes: [route], verify: options(), downstream, maxReplayBytes: MAX_REPLAY_BODY_BYTES });
    const idem = newIdempotencyKey();
    const body = { payee: 'shop.example', amount: 700 };
    const request = async () => {
      const invocation = await createInvocation(agent.privateKey, {
        chain,
        mandateId: m.id,
        action: 'payments.transfer',
        counterparty: body.payee,
        amount: EUR(body.amount),
        aud: AUD,
        args: { method: 'POST', path: '/payments', query: {}, media_type: 'application/json', body },
        idempotencyKey: idem,
      });
      return new Request(`${AUD}/payments`, { method: 'POST', headers: { 'content-type': 'application/json', ...authorizationHeaders(chain, invocation) }, body: JSON.stringify(body) });
    };
    expect((await gw.handle(await request())).status).toBe(201);
    const retry = await gw.handle(await request());
    expect(downstream).toHaveBeenCalledTimes(1);
    expect(retry.status).toBe(409);
    expect(await retry.json()).toMatchObject({ code: 'already_executed' });
  });
});

// ---------------------------------------------------------------- finding 4: capture latency on streamed bodies

describe('gateway: response capture', () => {
  it('does not hold a streamed 2xx response back for the capture budget', async () => {
    const m = mandate();
    const chain = await chainFor(m);
    const route: GatewayRoute = {
      method: 'POST',
      path: '/payments',
      action: 'payments.transfer',
      counterparty: (r) => (r.json() as { payee: string }).payee,
      amount: (r) => EUR((r.json() as { amount: number }).amount),
    };
    const gw = createGateway({
      routes: [route],
      verify: options(),
      downstream: async () =>
        new Response(
          new ReadableStream({
            start(c) {
              c.enqueue(new TextEncoder().encode('{"status":"accepted"'));
              // never closes: a long-poll or event stream
            },
          }),
          { status: 202 },
        ),
    });
    const body = { payee: 'shop.example', amount: 700 };
    const invocation = await createInvocation(agent.privateKey, {
      chain,
      mandateId: m.id,
      action: 'payments.transfer',
      counterparty: body.payee,
      amount: EUR(body.amount),
      aud: AUD,
      args: { method: 'POST', path: '/payments', query: {}, media_type: 'application/json', body },
      idempotencyKey: newIdempotencyKey(),
    });
    const res = await Promise.race([
      gw.handle(new Request(`${AUD}/payments`, { method: 'POST', headers: { 'content-type': 'application/json', ...authorizationHeaders(chain, invocation) }, body: JSON.stringify(body) })),
      new Promise<'hung'>((r) => setTimeout(() => r('hung'), 3000)),
    ]);
    expect(res).not.toBe('hung');
    // The client still gets the bytes that arrived before the capture gave up.
    const reader = (res as Response).body!.getReader();
    expect(new TextDecoder().decode((await reader.read()).value)).toBe('{"status":"accepted"');
    await reader.cancel();
  }, 10_000);
});

// ---------------------------------------------------------------- finding 4b: a finite body larger than maxReplayBytes

describe('gateway: response capture of a large streamed body', () => {
  it('returns a chunked 2xx response larger than maxReplayBytes', async () => {
    const m = mandate();
    const chain = await chainFor(m);
    const route: GatewayRoute = {
      method: 'POST',
      path: '/payments',
      action: 'payments.transfer',
      counterparty: (r) => (r.json() as { payee: string }).payee,
      amount: (r) => EUR((r.json() as { amount: number }).amount),
    };
    let sentChunks = 0;
    const gw = createGateway({
      routes: [route],
      verify: options(),
      maxReplayBytes: 1024,
      // 100 KiB in 16 KiB chunks, produced on demand like a proxied upstream body; no Content-Length.
      downstream: async () =>
        new Response(
          new ReadableStream({
            pull(c) {
              if (sentChunks++ >= 6) return c.close();
              c.enqueue(new Uint8Array(16 * 1024).fill(97));
            },
          }),
          { status: 200, headers: { 'content-type': 'text/plain' } },
        ),
    });
    const body = { payee: 'shop.example', amount: 700 };
    const invocation = await createInvocation(agent.privateKey, {
      chain,
      mandateId: m.id,
      action: 'payments.transfer',
      counterparty: body.payee,
      amount: EUR(body.amount),
      aud: AUD,
      args: { method: 'POST', path: '/payments', query: {}, media_type: 'application/json', body },
      idempotencyKey: newIdempotencyKey(),
    });
    const res = await Promise.race([
      gw.handle(new Request(`${AUD}/payments`, { method: 'POST', headers: { 'content-type': 'application/json', ...authorizationHeaders(chain, invocation) }, body: JSON.stringify(body) })),
      new Promise<'hung'>((r) => setTimeout(() => r('hung'), 3000)),
    ]);
    expect(res).not.toBe('hung');
  }, 10_000);

  it('returns it as well for a gateway with no idempotency store and an invocation without a key', async () => {
    const m = mandate();
    const chain = await chainFor(m);
    const route: GatewayRoute = {
      method: 'POST',
      path: '/payments',
      action: 'payments.transfer',
      counterparty: (r) => (r.json() as { payee: string }).payee,
      amount: (r) => EUR((r.json() as { amount: number }).amount),
    };
    let sentChunks = 0;
    const gw = createGateway({
      routes: [route],
      verify: options({ idempotency: undefined }),
      maxReplayBytes: 1024,
      downstream: async () =>
        new Response(
          new ReadableStream({
            pull(c) {
              if (sentChunks++ >= 6) return c.close();
              c.enqueue(new Uint8Array(16 * 1024).fill(97));
            },
          }),
          { status: 200 },
        ),
    });
    const body = { payee: 'shop.example', amount: 700 };
    const invocation = await createInvocation(agent.privateKey, {
      chain,
      mandateId: m.id,
      action: 'payments.transfer',
      counterparty: body.payee,
      amount: EUR(body.amount),
      aud: AUD,
      args: { method: 'POST', path: '/payments', query: {}, media_type: 'application/json', body },
    });
    const res = await Promise.race([
      gw.handle(new Request(`${AUD}/payments`, { method: 'POST', headers: { 'content-type': 'application/json', ...authorizationHeaders(chain, invocation) }, body: JSON.stringify(body) })),
      new Promise<'hung'>((r) => setTimeout(() => r('hung'), 3000)),
    ]);
    expect(res).not.toBe('hung');
  });
});

// ---------------------------------------------------------------- finding 3b: guardTool with a large maxReplayBytes

describe('guardTool: a result above the store bound', () => {
  it('still lets the retry learn that the call executed', async () => {
    const m = mandate();
    const chain = await chainFor(m);
    const opts = options();
    type A = { payee: string; amount: number };
    const handler = vi.fn(async () => ({ content: [{ type: 'text' as const, text: 'x'.repeat(300 * 1024) }] }));
    expect(() => guardTool<A>(handler, { ...opts, action: 'payments.transfer', counterparty: (a) => a.payee, amount: (a) => EUR(a.amount), maxReplayBytes: 1024 * 1024 })).toThrow(/maxReplayBytes/);
    // A store that refuses the result (here: anything above 10 bytes) must still learn that the call ran.
    const inner = new InMemoryIdempotencyStore();
    const picky: IdempotencyStore = Object.assign(Object.create(inner), {
      finish: (key: string, attempt: string, outcome: Parameters<IdempotencyStore['finish']>[2], result?: string) => {
        if (result !== undefined && result.length > 10) return Promise.reject(new RangeError('result too large'));
        return inner.finish(key, attempt, outcome, result);
      },
    });
    opts.idempotency = picky;
    const t = guardTool<A>(handler, { ...opts, action: 'payments.transfer', counterparty: (a) => a.payee, amount: (a) => EUR(a.amount), maxReplayBytes: MAX_STORED_RESULT_BYTES });
    const idem = newIdempotencyKey();
    const a = { payee: 'shop.example', amount: 100 };
    const call = async () => {
      const invocation = await createInvocation(agent.privateKey, { chain, mandateId: m.id, action: 'payments.transfer', counterparty: a.payee, amount: EUR(a.amount), aud: AUD, args: a, idempotencyKey: idem });
      return t(a, { _meta: { [META_KEY]: { chain, invocation } } });
    };
    await call();
    const retry = await call();
    expect(handler).toHaveBeenCalledTimes(1);
    expect(retry).toMatchObject({ structuredContent: { plenipo: { code: 'ALREADY_EXECUTED' } } });
  });
});

// ---------------------------------------------------------------- finding 4c: any 2xx body above 64 KiB, no store

describe('gateway without an idempotency store', () => {
  it('returns a plain 100 KB JSON response (no key, no store, default options)', async () => {
    const m = mandate();
    const chain = await chainFor(m);
    const route: GatewayRoute = {
      method: 'POST',
      path: '/payments',
      action: 'payments.transfer',
      counterparty: (r) => (r.json() as { payee: string }).payee,
      amount: (r) => EUR((r.json() as { amount: number }).amount),
    };
    const big = JSON.stringify({ rows: 'y'.repeat(100_000) });
    const gw = createGateway({ routes: [route], verify: options({ idempotency: undefined }), downstream: async () => new Response(big, { status: 200, headers: { 'content-type': 'application/json' } }) });
    const body = { payee: 'shop.example', amount: 700 };
    const invocation = await createInvocation(agent.privateKey, {
      chain,
      mandateId: m.id,
      action: 'payments.transfer',
      counterparty: body.payee,
      amount: EUR(body.amount),
      aud: AUD,
      args: { method: 'POST', path: '/payments', query: {}, media_type: 'application/json', body },
    });
    const res = await Promise.race([
      gw.handle(new Request(`${AUD}/payments`, { method: 'POST', headers: { 'content-type': 'application/json', ...authorizationHeaders(chain, invocation) }, body: JSON.stringify(body) })),
      new Promise<'hung'>((r) => setTimeout(() => r('hung'), 3000)),
    ]);
    expect(res).not.toBe('hung');
  }, 10_000);
});

// ---------------------------------------------------------------- note: a refused retry keeps its nonce

describe('a retry refused with IDEMPOTENCY_IN_PROGRESS', () => {
  it('cannot be replayed later by whoever captured it to read the stored result', async () => {
    const m = mandate();
    const chain = await chainFor(m);
    const opts = options();
    const idem = newIdempotencyKey();
    const first = await verify(chain, await pay(chain, m, 500, idem), opts, 500);
    if (first.decision !== 'ALLOW') throw new Error(first.code);
    const retry = await pay(chain, m, 500, idem); // e.g. logged by a proxy
    expect(await verify(chain, retry, opts, 500)).toMatchObject({ code: 'IDEMPOTENCY_IN_PROGRESS' });
    await opts.idempotency!.finish(first.idempotency!.key, first.idempotency!.attempt, 'executed', '{"iban":"IT60X0542811101000000123456"}');
    // The captured copy of the refused retry, sent again within maxInvocationAgeSeconds by someone else:
    const leaked = await verify(chain, retry, opts, 500);
    expect(leaked).not.toMatchObject({ code: 'ALREADY_EXECUTED', replay: { result: expect.any(String) } });
  });
});

// ---------------------------------------------------------------- finding: in-memory store never drops expired records

describe('InMemoryIdempotencyStore retention', () => {
  it('drops executed records after retention without anyone touching them', async () => {
    let t = 0;
    const s = new InMemoryIdempotencyStore({ retentionSeconds: 1, now: () => t });
    for (let i = 0; i < 1000; i++) {
      const k = `key-${i}-${'x'.repeat(16)}`;
      const c = await s.claim(k, 'fp');
      if (!c.claimed) throw new Error('not claimed');
      await s.finish(k, c.attempt, 'executed', 'r'.repeat(1024));
    }
    t = 10_000; // ten seconds later, every record is past retention
    for (let i = 0; i < 10; i++) {
      const k = `new-${i}-${'x'.repeat(16)}`;
      const c = await s.claim(k, 'fp');
      if (c.claimed) await s.finish(k, c.attempt, 'executed');
    }
    const size = (s as unknown as { entries: Map<string, unknown> }).entries.size;
    expect(size).toBeLessThan(100);
  });
});
