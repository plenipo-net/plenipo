/**
 * Idempotency keys (0.5): the store contract on every backend, the verifier rules, the MCP guard and the
 * HTTP gateway, and the per-call maximum age of status lists.
 */
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { randomUUID } from 'node:crypto';
import pg from 'pg';
import { Redis } from 'ioredis';
import { exportJWK, generateKeyPair } from 'jose';
import {
  authorizationHeaders,
  createGateway,
  createInvocation,
  createMandate,
  generateAgentKey,
  idempotencyScope,
  chainHash,
  InMemoryIdempotencyStore,
  InMemoryNonceStore,
  InMemorySpendingLedger,
  InMemoryStatusListStore,
  ManagedStatusList,
  mandateHash,
  newIdempotencyKey,
  REPLAY_HEADER,
  StatusListCache,
  StatusListPublisher,
  DEFAULT_STATUS_TTL_SECONDS,
  verifyAuthorization,
  type AgentKey,
  type Amount,
  type Decision,
  type GatewayRoute,
  type IdempotencyStore,
  type Mandate,
  type MandateChain,
  type StatusFetcher,
  type VerifyOptions,
} from '../src/index.js';
import { guardTool, META_KEY, OUTCOME_META_KEY, REPLAY_META_KEY } from '../src/mcp.js';
import { fromIoredis, migratePostgres, PostgresIdempotencyStore, PostgresSpendingLedger, RedisIdempotencyStore, RedisSpendingLedger } from '../src/stores/index.js';
import { createTestPidProvider, createTestWallet, type TestPidProvider, type TestWallet } from '../src/testing.js';
import { startPostgres, startRedis } from './stores-engines.js';

const pgEngine = await startPostgres();
const redisEngine = await startRedis();
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const AUD = 'https://bank.example';
const EUR = (value: number): Amount => ({ value, currency: 'EUR' });

let provider: TestPidProvider;
let wallet: TestWallet;
let agent: AgentKey;
let pool: pg.Pool | undefined;
let io: Redis | undefined;
/** Extra connections opened by the contract tests, closed before the engines stop. */
const extraPools: pg.Pool[] = [];
const extraRedis: Redis[] = [];

beforeAll(async () => {
  provider = await createTestPidProvider('https://pid-idem.example');
  wallet = await createTestWallet();
  wallet.storePid(await provider.issuePid(wallet.holderJwk, { given_name: 'Grace', family_name: 'Hopper' }));
  agent = await generateAgentKey();
  if (pgEngine.ok) {
    pool = new pg.Pool({ connectionString: pgEngine.url, max: 12 });
  }
  if (redisEngine.ok) {
    io = new Redis(redisEngine.url, { lazyConnect: true, maxRetriesPerRequest: 1 });
    await io.connect();
  }
});

afterAll(async () => {
  await Promise.all(extraPools.map((p) => p.end()));
  for (const r of extraRedis) r.disconnect();
  await pool?.end();
  io?.disconnect();
  if (pgEngine.ok) await pgEngine.stop();
  if (redisEngine.ok) await redisEngine.stop();
});

// ---------------------------------------------------------------- the store contract

type Factory = (opts?: { leaseSeconds?: number; retentionSeconds?: number }) => Promise<[IdempotencyStore, IdempotencyStore]>;

const key = () => `k-${randomUUID()}`;

function contract(name: string, enabled: () => boolean, make: Factory) {
  describe.skipIf(!enabled())(`${name}: idempotency store`, () => {
    it('lets exactly one of many parallel claims take a free key, across two connections', async () => {
      const [a, b] = await make();
      const k = key();
      const results = await Promise.all(Array.from({ length: 20 }, (_, i) => (i % 2 ? a : b).claim(k, 'fp')));
      expect(results.filter((r) => r.claimed)).toHaveLength(1);
      const winner = results.find((r) => r.claimed) as { attempt: string };
      for (const r of results.filter((x) => !x.claimed)) {
        expect(r).toMatchObject({ claimed: false, record: { key: k, fingerprint: 'fp', state: 'in_progress', attempt: winner.attempt } });
      }
    });

    it('keeps an executed result for replays, and ignores finishes by other attempts', async () => {
      const [a, b] = await make();
      const k = key();
      const c = await a.claim(k, 'fp');
      if (!c.claimed) throw new Error('not claimed');
      await b.finish(k, randomUUID(), 'not_executed');
      await b.attach(k, c.attempt, '6f1c8a3e-62a3-4d3a-9d6e-2a1f3c4b5d6e');
      await a.finish(k, c.attempt, 'executed', '{"ok":true}');
      expect(await b.get(k)).toMatchObject({ state: 'executed', result: '{"ok":true}', reservation: '6f1c8a3e-62a3-4d3a-9d6e-2a1f3c4b5d6e' });
      // Executed is final: nothing gives it back.
      await a.finish(k, c.attempt, 'not_executed');
      expect(await a.resolve(k, 'not_executed', c.attempt)).toBe(false);
      const again = await b.claim(k, 'fp');
      expect(again).toMatchObject({ claimed: false, record: { state: 'executed' } });
    });

    it('frees a key whose attempt did not run, and blocks one whose outcome is unknown until resolved', async () => {
      const [a, b] = await make();
      const k1 = key();
      const c1 = await a.claim(k1, 'fp');
      if (!c1.claimed) throw new Error('not claimed');
      await a.finish(k1, c1.attempt, 'not_executed');
      expect(await b.get(k1)).toBeUndefined();
      const c1b = await b.claim(k1, 'fp2');
      expect(c1b.claimed).toBe(true);

      const k2 = key();
      const c2 = await a.claim(k2, 'fp');
      if (!c2.claimed) throw new Error('not claimed');
      await a.finish(k2, c2.attempt, 'unknown');
      expect(await b.claim(k2, 'fp')).toMatchObject({ claimed: false, record: { state: 'unknown' } });
      expect((await b.unresolved()).map((r) => r.key)).toContain(k2);
      expect(await b.resolve(k2, 'not_executed', c2.attempt)).toBe(true);
      expect((await b.unresolved()).map((r) => r.key)).not.toContain(k2);
      expect((await a.claim(k2, 'fp')).claimed).toBe(true);
    });

    it('lets a late "executed" land on a freed key nobody took, but not on a key taken again', async () => {
      const [a, b] = await make();
      const k = key();
      const c = await a.claim(k, 'fp');
      if (!c.claimed) throw new Error('not claimed');
      await a.finish(k, c.attempt, 'unknown');
      expect(await b.resolve(k, 'not_executed', c.attempt)).toBe(true);
      await a.finish(k, c.attempt, 'executed', 'late');
      expect(await b.get(k)).toMatchObject({ state: 'executed', result: 'late', attempt: c.attempt });

      const k2 = key();
      const c2 = await a.claim(k2, 'fp');
      if (!c2.claimed) throw new Error('not claimed');
      await a.finish(k2, c2.attempt, 'not_executed');
      const taken = await b.claim(k2, 'fp');
      if (!taken.claimed) throw new Error('not claimed');
      await a.finish(k2, c2.attempt, 'executed', 'late');
      expect(await b.get(k2)).toMatchObject({ state: 'in_progress', attempt: taken.attempt });
    });

    it('turns an attempt held past its lease into unknown, and lists it for reconciliation', async () => {
      const [a, b] = await make({ leaseSeconds: 0.3 });
      const k = key();
      const c = await a.claim(k, 'fp');
      expect(c.claimed).toBe(true);
      expect(await b.get(k)).toMatchObject({ state: 'in_progress' });
      await sleep(450);
      expect(await b.get(k)).toMatchObject({ state: 'unknown' });
      expect((await b.unresolved()).map((r) => r.key)).toContain(k);
      expect(await b.claim(k, 'fp')).toMatchObject({ claimed: false, record: { state: 'unknown' } });
      expect(await a.resolve(k, 'executed', (c as { attempt: string }).attempt)).toBe(true);
      expect(await b.get(k)).toMatchObject({ state: 'executed' });
    });

    it('forgets executed records after their retention, never unresolved ones', async () => {
      const [a, b] = await make({ retentionSeconds: 0.3, leaseSeconds: 60 });
      const done = key();
      const c = await a.claim(done, 'fp');
      if (!c.claimed) throw new Error('not claimed');
      await a.finish(done, c.attempt, 'executed', 'r');
      const open = key();
      const o = await a.claim(open, 'fp');
      if (!o.claimed) throw new Error('not claimed');
      await a.finish(open, o.attempt, 'unknown');
      await sleep(500);
      expect(await b.get(done)).toBeUndefined();
      expect((await b.claim(done, 'fp')).claimed).toBe(true);
      expect(await b.get(open)).toMatchObject({ state: 'unknown' });
    });

    it('resolves only the attempt it names: an outcome learned about one attempt never settles a newer one', async () => {
      const [a, b] = await make();
      const k = key();
      const first = await a.claim(k, 'fp');
      if (!first.claimed) throw new Error('not claimed');
      await a.finish(k, first.attempt, 'unknown');
      const [listed] = (await b.unresolved({ limit: 10_000 })).filter((r) => r.key === k);
      expect(listed.attempt).toBe(first.attempt);
      expect(await b.resolve(k, 'not_executed', first.attempt)).toBe(true);
      const second = await b.claim(k, 'fp');
      if (!second.claimed) throw new Error('not claimed');
      // A stale listing names the first attempt: nothing happens to the second.
      expect(await a.resolve(k, 'not_executed', listed.attempt)).toBe(false);
      expect(await a.resolve(k, 'executed', listed.attempt)).toBe(false);
      expect(await a.claim(k, 'fp')).toMatchObject({ claimed: false, record: { state: 'in_progress', attempt: second.attempt } });
      await expect(a.resolve(k, 'executed', 'not-an-attempt')).rejects.toThrow(/attempt/);
    });

    it('validates what it is given', async () => {
      const [a] = await make();
      await expect(a.claim('', 'fp')).rejects.toThrow();
      await expect(a.claim('x'.repeat(300), 'fp')).rejects.toThrow();
      await expect(a.claim(key(), '')).rejects.toThrow();
      await expect(a.finish(key(), randomUUID(), 'maybe' as never)).rejects.toThrow();
      await expect(a.finish(key(), randomUUID(), 'executed', 'x'.repeat(300 * 1024))).rejects.toThrow();
    });
  });
}

contract('memory', () => true, async (opts = {}) => {
  const s = new InMemoryIdempotencyStore(opts);
  return [s, s];
});

contract('Postgres', () => pgEngine.ok, async (opts = {}) => {
  const tablePrefix = `i${randomUUID().replace(/-/g, '').slice(0, 12)}_`;
  await migratePostgres(pool!, { tablePrefix });
  const other = new pg.Pool({ connectionString: (pgEngine as { url: string }).url, max: 4 });
  extraPools.push(other);
  return [new PostgresIdempotencyStore(pool!, { tablePrefix, ...opts }), new PostgresIdempotencyStore(other, { tablePrefix, ...opts })];
});

contract('Redis', () => redisEngine.ok, async (opts = {}) => {
  const prefix = `idem-${randomUUID()}`;
  const other = new Redis((redisEngine as { url: string }).url, { lazyConnect: true, maxRetriesPerRequest: 1 });
  await other.connect();
  extraRedis.push(other);
  return [new RedisIdempotencyStore(fromIoredis(io!), { prefix, ...opts }), new RedisIdempotencyStore(fromIoredis(other), { prefix, ...opts })];
});

describe.skipIf(!redisEngine.ok)('Redis idempotency keys', () => {
  it('keeps every key under one hash tag and hashes caller keys into names', async () => {
    const prefix = `tag-${randomUUID()}`;
    const s = new RedisIdempotencyStore(fromIoredis(io!), { prefix });
    const c = await s.claim('a{b}c', 'fp');
    if (!c.claimed) throw new Error('not claimed');
    await s.finish('a{b}c', c.attempt, 'unknown');
    const keys = await io!.keys(`*${prefix}*`);
    expect(keys.length).toBeGreaterThanOrEqual(2);
    for (const k of keys) {
      expect(k.startsWith(`{${prefix}:idem}:`)).toBe(true);
      expect(k).not.toContain('a{b}c');
    }
  });
});

// ---------------------------------------------------------------- the verifier

function mandate(overrides: Partial<Parameters<typeof createMandate>[0]> = {}): Mandate {
  return createMandate({
    agentJwk: agent.publicJwk,
    actions: ['payments.transfer', 'accounts.read'],
    counterparties: ['shop.example'],
    limits: { currency: 'EUR', per_operation: 50_000, total: 100_000 },
    ...overrides,
  });
}

async function chainFor(m: Mandate): Promise<MandateChain> {
  return { root: await wallet.approveMandate(m), delegations: [] };
}

interface Pay {
  value: number;
  counterparty?: string;
  idem?: string;
  args?: unknown;
  nonce?: string;
}

function payment(chain: MandateChain, m: Mandate, p: Pay): Promise<string> {
  return createInvocation(agent.privateKey, {
    chain,
    mandateId: m.id,
    action: 'payments.transfer',
    counterparty: p.counterparty ?? 'shop.example',
    amount: EUR(p.value),
    aud: AUD,
    args: p.args ?? { payee: p.counterparty ?? 'shop.example', amount: p.value },
    ...(p.idem ? { idempotencyKey: p.idem } : {}),
    ...(p.nonce ? { nonce: p.nonce } : {}),
  });
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

const expectFor = (p: Pay): VerifyOptions['expected'] => ({
  action: 'payments.transfer',
  counterparty: p.counterparty ?? 'shop.example',
  amount: EUR(p.value),
  args: p.args ?? { payee: p.counterparty ?? 'shop.example', amount: p.value },
});

async function verify(chain: MandateChain, inv: string, opts: VerifyOptions, p: Pay): Promise<Decision> {
  return verifyAuthorization(chain, inv, { ...opts, expected: expectFor(p) });
}

function allow(d: Decision) {
  if (d.decision !== 'ALLOW') throw new Error(`expected ALLOW, got ${d.code}: ${d.reason}`);
  return d;
}

describe('verifyAuthorization with idempotency keys', () => {
  it('lets one attempt run per key: in progress, then the stored result, and never a second reservation', async () => {
    const m = mandate();
    const chain = await chainFor(m);
    const opts = options();
    const idem = newIdempotencyKey();
    const p = { value: 30_000, idem };
    const first = allow(await verify(chain, await payment(chain, m, p), opts, p));
    expect(first.idempotency).toMatchObject({ key: idempotencyScope(AUD, chainHash(chain), idem) });
    expect(first.reservation).toBeDefined();

    expect(await verify(chain, await payment(chain, m, p), opts, p)).toMatchObject({ decision: 'DENY', code: 'IDEMPOTENCY_IN_PROGRESS' });

    await opts.idempotency!.finish(first.idempotency!.key, first.idempotency!.attempt, 'executed', 'receipt-1');
    await opts.ledger!.commit(first.reservation!);
    const retry = await payment(chain, m, p);
    expect(await verify(chain, retry, opts, p)).toMatchObject({ decision: 'DENY', code: 'ALREADY_EXECUTED', replay: { result: 'receipt-1' } });
    // The retry's nonce was spent: a copy of it cannot read the result again.
    expect(await verify(chain, retry, opts, p)).toMatchObject({ decision: 'DENY', code: 'REPLAY' });
    // Only the first attempt was counted against the total.
    expect(await opts.ledger!.spent(mandateHash(m), 'EUR')).toBe(30_000);
  });

  it('refuses a key reused for a different request', async () => {
    const m = mandate();
    const chain = await chainFor(m);
    const opts = options();
    const idem = newIdempotencyKey();
    allow(await verify(chain, await payment(chain, m, { value: 100, idem }), opts, { value: 100, idem }));
    const other = { value: 200, idem };
    expect(await verify(chain, await payment(chain, m, other), opts, other)).toMatchObject({ decision: 'DENY', code: 'IDEMPOTENCY_CONFLICT' });
    const otherArgs = { value: 100, idem, args: { payee: 'shop.example', amount: 100, reference: 'B' } };
    expect(await verify(chain, await payment(chain, m, otherArgs), opts, otherArgs)).toMatchObject({ decision: 'DENY', code: 'IDEMPOTENCY_CONFLICT' });
  });

  it('blocks retries of an attempt with an unknown outcome until it is reconciled', async () => {
    const m = mandate();
    const chain = await chainFor(m);
    const opts = options();
    const p = { value: 1_000, idem: newIdempotencyKey() };
    const first = allow(await verify(chain, await payment(chain, m, p), opts, p));
    await opts.idempotency!.finish(first.idempotency!.key, first.idempotency!.attempt, 'unknown');
    expect(await verify(chain, await payment(chain, m, p), opts, p)).toMatchObject({ decision: 'DENY', code: 'IDEMPOTENCY_UNRESOLVED' });
    expect(await opts.idempotency!.resolve(first.idempotency!.key, 'not_executed', first.idempotency!.attempt)).toBe(true);
    allow(await verify(chain, await payment(chain, m, p), opts, p));
  });

  it('follows a shared ledger: a committed reservation means executed, a released one frees the key', async () => {
    const m = mandate();
    const chain = await chainFor(m);
    const states = new Map<string, string>();
    class Tracking extends InMemorySpendingLedger {
      reserve(...a: Parameters<InMemorySpendingLedger['reserve']>) {
        const id = super.reserve(...a);
        if (id) states.set(id, 'pending');
        return id;
      }
      async reservation(id: string) {
        return states.has(id) ? { state: states.get(id)! } : undefined;
      }
    }
    const opts = options({ ledger: new Tracking() });
    const a = { value: 500, idem: newIdempotencyKey() };
    const first = allow(await verify(chain, await payment(chain, m, a), opts, a));
    await opts.idempotency!.finish(first.idempotency!.key, first.idempotency!.attempt, 'unknown');
    expect(await verify(chain, await payment(chain, m, a), opts, a)).toMatchObject({ code: 'IDEMPOTENCY_UNRESOLVED' });
    states.set(first.reservation!, 'committed');
    expect(await verify(chain, await payment(chain, m, a), opts, a)).toMatchObject({ code: 'ALREADY_EXECUTED' });
    expect(await opts.idempotency!.get(first.idempotency!.key)).toMatchObject({ state: 'executed' });

    const b = { value: 600, idem: newIdempotencyKey() };
    const second = allow(await verify(chain, await payment(chain, m, b), opts, b));
    await opts.idempotency!.finish(second.idempotency!.key, second.idempotency!.attempt, 'unknown');
    states.set(second.reservation!, 'released');
    const third = allow(await verify(chain, await payment(chain, m, b), opts, b));
    expect(third.idempotency!.attempt).not.toBe(second.idempotency!.attempt);
  });

  it('never claims a key for a refused attempt, and gives it back when the reservation or the nonce fails', async () => {
    const m = mandate({ limits: { currency: 'EUR', per_operation: 50_000, total: 1_000 } });
    const chain = await chainFor(m);
    const opts = options();
    const idem = newIdempotencyKey();
    const outside = { value: 10, counterparty: 'evil.example', idem };
    expect(await verify(chain, await payment(chain, m, outside), opts, outside)).toMatchObject({ code: 'COUNTERPARTY_NOT_PERMITTED' });
    expect(await opts.idempotency!.get(idempotencyScope(AUD, chainHash(chain), idem))).toBeUndefined();

    const big = { value: 5_000, idem };
    expect(await verify(chain, await payment(chain, m, big), opts, big)).toMatchObject({ code: 'LIMIT_TOTAL' });
    expect(await opts.idempotency!.get(idempotencyScope(AUD, chainHash(chain), idem))).toBeUndefined();

    const p = { value: 100, idem: newIdempotencyKey(), nonce: 'n-1' };
    allow(await verify(chain, await payment(chain, m, { value: 1, nonce: 'n-1' }), opts, { value: 1 }));
    expect(await verify(chain, await payment(chain, m, p), opts, p)).toMatchObject({ code: 'REPLAY' });
    expect(await opts.idempotency!.get(idempotencyScope(AUD, chainHash(chain), p.idem))).toBeUndefined();
    expect(await opts.ledger!.spent(mandateHash(m), 'EUR')).toBe(1);
  });

  it('scopes keys to the chain and the audience', async () => {
    const m1 = mandate();
    const m2 = mandate();
    const c1 = await chainFor(m1);
    const c2 = await chainFor(m2);
    const opts = options();
    const idem = newIdempotencyKey();
    const p = { value: 100, idem };
    allow(await verify(c1, await payment(c1, m1, p), opts, p));
    allow(await verify(c2, await payment(c2, m2, p), opts, p));
    expect(idempotencyScope(AUD, chainHash(c1), idem)).not.toBe(idempotencyScope('https://other.example', chainHash(c1), idem));
  });

  it('refuses a key it cannot honour, a key without arguments, and invocation members it does not know', async () => {
    const m = mandate();
    const chain = await chainFor(m);
    const p = { value: 100, idem: newIdempotencyKey() };
    const inv = await payment(chain, m, p);
    expect(await verify(chain, inv, options({ idempotency: undefined }), p)).toMatchObject({ decision: 'DENY', code: 'CONFIGURATION' });

    await expect(createInvocation(agent.privateKey, { chain, mandateId: m.id, action: 'payments.transfer', aud: AUD, idempotencyKey: newIdempotencyKey() })).rejects.toThrow(/args/);
    await expect(createInvocation(agent.privateKey, { chain, mandateId: m.id, action: 'payments.transfer', aud: AUD, args: {}, idempotencyKey: 'short' })).rejects.toThrow(/idempotencyKey/);

    // Hand-signed payloads: the verifier checks shape strictly whatever the agent library did.
    const { SignJWT } = await import('jose');
    const base = { mandate: m.id, action: 'payments.transfer', counterparty: 'shop.example', amount: EUR(100), aud: AUD, iat: Math.floor(Date.now() / 1000), chain_hash: chainHash(chain) };
    const sign = (payload: Record<string, unknown>) => new SignJWT(payload).setProtectedHeader({ alg: 'ES256', typ: 'plenipo-invocation+jwt' }).sign(agent.privateKey);
    const noArgs = await sign({ ...base, nonce: randomUUID(), idem: newIdempotencyKey() });
    expect(await verifyAuthorization(chain, noArgs, options())).toMatchObject({ code: 'MALFORMED', reason: expect.stringMatching(/idem requires args_hash/) });
    const extra = await sign({ ...base, nonce: randomUUID(), max_retries: 3 });
    expect(await verifyAuthorization(chain, extra, options())).toMatchObject({ code: 'MALFORMED', reason: expect.stringMatching(/unknown member max_retries/) });
  });

  it('works unchanged for invocations without a key', async () => {
    const m = mandate();
    const chain = await chainFor(m);
    const opts = options();
    const p = { value: 100 };
    const d = allow(await verify(chain, await payment(chain, m, p), opts, p));
    expect(d.idempotency).toBeUndefined();
    allow(await verify(chain, await payment(chain, m, p), opts, p));
  });
});

// ---------------------------------------------------------------- the MCP guard

describe('guardTool with idempotency keys', () => {
  type Args = { payee: string; amount: number };
  function tool(handler: (args: Args) => Promise<{ content: Array<{ type: 'text'; text: string }>; isError?: boolean; _meta?: Record<string, unknown> }>, opts: VerifyOptions, extra: { maxReplayBytes?: number } = {}) {
    return guardTool<Args>(async (args) => handler(args), {
      ...opts,
      action: 'payments.transfer',
      counterparty: (a) => a.payee,
      amount: (a) => EUR(a.amount),
      ...extra,
    });
  }
  async function call(t: ReturnType<typeof tool>, chain: MandateChain, m: Mandate, args: Args, idem: string) {
    const invocation = await createInvocation(agent.privateKey, { chain, mandateId: m.id, action: 'payments.transfer', counterparty: args.payee, amount: EUR(args.amount), aud: AUD, args, idempotencyKey: idem });
    return t(args, { _meta: { [META_KEY]: { chain, invocation } } });
  }

  it('answers a retry with the stored result instead of paying twice', async () => {
    const m = mandate();
    const chain = await chainFor(m);
    const opts = options();
    const handler = vi.fn(async (a: Args) => ({ content: [{ type: 'text' as const, text: `paid ${a.amount}` }] }));
    const t = tool(handler, opts);
    const idem = newIdempotencyKey();
    const args = { payee: 'shop.example', amount: 4_200 };
    const first = await call(t, chain, m, args, idem);
    const retry = await call(t, chain, m, args, idem);
    expect(handler).toHaveBeenCalledTimes(1);
    expect(first.content[0].text).toBe('paid 4200');
    expect(retry.content[0].text).toBe('paid 4200');
    expect(retry._meta?.[REPLAY_META_KEY]).toBe(true);
    expect(await opts.ledger!.spent(mandateHash(m), 'EUR')).toBe(4_200);
  });

  it('after a crash mid-call, refuses retries until the bank reconciles, and never runs the tool again', async () => {
    const m = mandate();
    const chain = await chainFor(m);
    const opts = options();
    let balance = 10_000;
    const handler = vi.fn(async (a: Args) => {
      balance -= a.amount; // the money left...
      throw new Error('core banking timeout'); // ...and then the call failed
    });
    const t = tool(handler, opts);
    const idem = newIdempotencyKey();
    const args = { payee: 'shop.example', amount: 3_000 };
    await expect(call(t, chain, m, args, idem)).rejects.toThrow(/timeout/);
    const retry = await call(t, chain, m, args, idem);
    expect(retry).toMatchObject({ isError: true, structuredContent: { plenipo: { decision: 'DENY', code: 'IDEMPOTENCY_UNRESOLVED' } } });
    expect(handler).toHaveBeenCalledTimes(1);
    expect(balance).toBe(7_000);
    // The bank finds the debit and reconciles: the retry learns the call ran.
    const [record] = await opts.idempotency!.unresolved();
    expect(await opts.idempotency!.resolve(record.key, 'executed', record.attempt)).toBe(true);
    const after = await call(t, chain, m, args, idem);
    expect(after).toMatchObject({ structuredContent: { plenipo: { code: 'ALREADY_EXECUTED' } } });
    expect(handler).toHaveBeenCalledTimes(1);
  });

  it('frees the key when the tool states the action did not run', async () => {
    const m = mandate();
    const chain = await chainFor(m);
    const opts = options();
    let fail = true;
    const handler = vi.fn(async () => {
      if (fail) {
        fail = false;
        return { isError: true, content: [{ type: 'text' as const, text: 'insufficient funds' }], _meta: { [OUTCOME_META_KEY]: 'not-executed' } };
      }
      return { content: [{ type: 'text' as const, text: 'paid' }] };
    });
    const t = tool(handler, opts);
    const idem = newIdempotencyKey();
    const args = { payee: 'shop.example', amount: 100 };
    expect((await call(t, chain, m, args, idem)).isError).toBe(true);
    expect((await call(t, chain, m, args, idem)).content[0].text).toBe('paid');
    expect(handler).toHaveBeenCalledTimes(2);
  });

  it('does not keep results above maxReplayBytes', async () => {
    const m = mandate();
    const chain = await chainFor(m);
    const opts = options();
    const t = tool(async () => ({ content: [{ type: 'text' as const, text: 'x'.repeat(2_000) }] }), opts, { maxReplayBytes: 1_000 });
    const idem = newIdempotencyKey();
    const args = { payee: 'shop.example', amount: 100 };
    await call(t, chain, m, args, idem);
    const retry = await call(t, chain, m, args, idem);
    expect(retry).toMatchObject({ isError: true, structuredContent: { plenipo: { code: 'ALREADY_EXECUTED' } } });
  });
});

// ---------------------------------------------------------------- the HTTP gateway

describe('gateway with idempotency keys', () => {
  const route: GatewayRoute = {
    method: 'POST',
    path: '/payments',
    action: 'payments.transfer',
    counterparty: (r) => (r.json() as { payee: string }).payee,
    amount: (r) => EUR((r.json() as { amount: number }).amount),
  };

  async function request(chain: MandateChain, m: Mandate, body: { payee: string; amount: number }, idem: string) {
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
    return new Request(`${AUD}/payments`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', ...authorizationHeaders(chain, invocation) },
      body: JSON.stringify(body),
    });
  }

  it('replays the stored response and does not call the API twice', async () => {
    const m = mandate();
    const chain = await chainFor(m);
    const downstream = vi.fn(async () => new Response(JSON.stringify({ id: 'pay-1' }), { status: 201, headers: { 'content-type': 'application/json' } }));
    const gw = createGateway({ routes: [route], verify: options(), downstream });
    const idem = newIdempotencyKey();
    const body = { payee: 'shop.example', amount: 700 };
    const first = await gw.handle(await request(chain, m, body, idem));
    expect(first.status).toBe(201);
    expect(await first.json()).toEqual({ id: 'pay-1' });
    const retry = await gw.handle(await request(chain, m, body, idem));
    expect(retry.status).toBe(201);
    expect(retry.headers.get(REPLAY_HEADER)).toBe('true');
    expect(retry.headers.get('content-type')).toBe('application/json');
    expect(await retry.json()).toEqual({ id: 'pay-1' });
    expect(downstream).toHaveBeenCalledTimes(1);
  });

  it('answers 409 idempotency_unresolved after a 5xx, and 422 for a key reused with another body', async () => {
    const m = mandate();
    const chain = await chainFor(m);
    const downstream = vi.fn(async () => new Response('upstream timeout', { status: 504 }));
    const gw = createGateway({ routes: [route], verify: options(), downstream });
    const idem = newIdempotencyKey();
    const body = { payee: 'shop.example', amount: 700 };
    expect((await gw.handle(await request(chain, m, body, idem))).status).toBe(504);
    const retry = await gw.handle(await request(chain, m, body, idem));
    expect(retry.status).toBe(409);
    expect(await retry.json()).toMatchObject({ code: 'idempotency_unresolved' });
    const other = await gw.handle(await request(chain, m, { ...body, amount: 800 }, idem));
    expect(other.status).toBe(422);
    expect(await other.json()).toMatchObject({ code: 'idempotency_conflict' });
    expect(downstream).toHaveBeenCalledTimes(1);
  });

  it('frees the key on a definite refusal (4xx) and tells a concurrent retry to come back later', async () => {
    const m = mandate();
    const chain = await chainFor(m);
    let release: () => void = () => undefined;
    const gate = new Promise<void>((r) => (release = r));
    let calls = 0;
    const gw = createGateway({
      routes: [route],
      verify: options(),
      async downstream() {
        calls++;
        if (calls === 1) return new Response('{"error":"limit"}', { status: 422 });
        await gate;
        return new Response('{"id":"pay-2"}', { status: 201 });
      },
    });
    const idem = newIdempotencyKey();
    const body = { payee: 'shop.example', amount: 100 };
    expect((await gw.handle(await request(chain, m, body, idem))).status).toBe(422);
    const slow = gw.handle(await request(chain, m, body, idem));
    await sleep(50);
    const busy = await gw.handle(await request(chain, m, body, idem));
    expect(busy.status).toBe(409);
    expect(busy.headers.get('retry-after')).toBe('5');
    expect(await busy.json()).toMatchObject({ code: 'idempotency_in_progress' });
    release();
    expect((await slow).status).toBe(201);
    expect(calls).toBe(2);
  });
});

// ---------------------------------------------------------------- revocation latency

describe('maximum age of status lists', () => {
  const PLATFORM = 'https://platform.example';
  let publisher: StatusListPublisher;
  let platformJwk: Record<string, unknown>;

  beforeAll(async () => {
    const pair = await generateKeyPair('ES256', { extractable: true });
    platformJwk = (await exportJWK(pair.publicKey)) as Record<string, unknown>;
    publisher = new StatusListPublisher({ uri: `${PLATFORM}/status/1`, signingKey: pair.privateKey, iss: PLATFORM, size: 1024 });
  });

  it('publishes a 60 s ttl by default, in the publisher and in ManagedStatusList', async () => {
    const { decodeJwt } = await import('jose');
    expect(DEFAULT_STATUS_TTL_SECONDS).toBe(60);
    expect(decodeJwt(await publisher.token()).ttl).toBe(60);
    const pair = await generateKeyPair('ES256', { extractable: true });
    const managed = new ManagedStatusList({ id: 'l', uri: `${PLATFORM}/status/m`, signingKey: pair.privateKey, store: new InMemoryStatusListStore(), size: 1024 });
    expect(decodeJwt(await managed.token()).ttl).toBe(60);
  });

  it('lets a payment call see a revocation the cache would hide, and asks HTTP caches for a fresh copy', async () => {
    const ref = publisher.allocate();
    const m = mandate({ status: ref });
    const chain = await chainFor(m);
    const fetcher = vi.fn<StatusFetcher>(async () => publisher.token());
    const cache = new StatusListCache(300);
    const base = () =>
      options({
        idempotency: undefined,
        statusFetcher: fetcher,
        statusCache: cache,
        mandateStatusTrust: { trustedIssuers: [{ iss: PLATFORM, jwk: platformJwk }] },
      });
    const p = { value: 100 };
    allow(await verify(chain, await payment(chain, m, p), base(), p));
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(fetcher.mock.calls[0][1]).toBeUndefined();

    publisher.revoke(ref);
    // A read keeps using the cached list...
    allow(await verify(chain, await payment(chain, m, p), base(), p));
    expect(fetcher).toHaveBeenCalledTimes(1);
    // ...a payment that requires a list at most 5 s old does not.
    const now = Math.floor(Date.now() / 1000);
    const fresh = await verify(chain, await payment(chain, m, p), { ...base(), maxStatusAgeSeconds: 5, now: now + 10 }, p);
    expect(fresh).toMatchObject({ decision: 'DENY', code: 'REVOKED' });
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(fetcher.mock.calls[1][1]).toEqual({ maxAgeSeconds: 5 });
    expect(await verify(chain, await payment(chain, m, p), { ...base(), maxStatusAgeSeconds: -1 }, p)).toMatchObject({ code: 'CONFIGURATION' });
  });

  it('applies a per-route maximum age in the gateway', async () => {
    const ref = publisher.allocate();
    const m = mandate({ status: ref });
    const chain = await chainFor(m);
    const fetcher = vi.fn<StatusFetcher>(async () => publisher.token());
    const verifyOpts = options({
      idempotency: undefined,
      statusFetcher: fetcher,
      statusCache: new StatusListCache(300),
      mandateStatusTrust: { trustedIssuers: [{ iss: PLATFORM, jwk: platformJwk }] },
    });
    const pay: GatewayRoute = {
      method: 'POST',
      path: '/payments',
      action: 'payments.transfer',
      counterparty: (r) => (r.json() as { payee: string }).payee,
      amount: (r) => EUR((r.json() as { amount: number }).amount),
      maxStatusAgeSeconds: 0,
    };
    const gw = createGateway({ routes: [pay], verify: verifyOpts, downstream: async () => new Response('{}', { status: 201 }) });
    const send = async () => {
      const body = { payee: 'shop.example', amount: 100 };
      const invocation = await createInvocation(agent.privateKey, {
        chain,
        mandateId: m.id,
        action: 'payments.transfer',
        counterparty: body.payee,
        amount: EUR(body.amount),
        aud: AUD,
        args: { method: 'POST', path: '/payments', query: {}, media_type: 'application/json', body },
      });
      return gw.handle(new Request(`${AUD}/payments`, { method: 'POST', headers: { 'content-type': 'application/json', ...authorizationHeaders(chain, invocation) }, body: JSON.stringify(body) }));
    };
    expect((await send()).status).toBe(201);
    publisher.revoke(ref);
    expect((await send()).status).toBe(401);
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(() => createGateway({ routes: [{ ...pay, maxStatusAgeSeconds: -5 }], verify: verifyOpts })).toThrow(/maxStatusAgeSeconds/);
  });
});

// ---------------------------------------------------------------- shared stores end to end

describe.skipIf(!pgEngine.ok)('Postgres end to end: a retry after a crash follows the ledger reconciliation', () => {
  it('blocks the retry, then answers it as executed once the reservation is reconciled', async () => {
    const tablePrefix = `e${randomUUID().replace(/-/g, '').slice(0, 12)}_`;
    await migratePostgres(pool!, { tablePrefix });
    const ledger = new PostgresSpendingLedger(pool!, { tablePrefix });
    const idempotency = new PostgresIdempotencyStore(pool!, { tablePrefix, leaseSeconds: 0.2 });
    const m = mandate();
    const chain = await chainFor(m);
    const opts = options({ ledger, idempotency });
    const p = { value: 2_500, idem: newIdempotencyKey() };
    const first = allow(await verify(chain, await payment(chain, m, p), opts, p));
    // The process dies here: neither the reservation nor the key is ever settled.
    await sleep(300);
    expect(await verify(chain, await payment(chain, m, p), opts, p)).toMatchObject({ code: 'IDEMPOTENCY_UNRESOLVED' });
    await ledger.reconcile(first.reservation!, 'executed');
    expect(await verify(chain, await payment(chain, m, p), opts, p)).toMatchObject({ code: 'ALREADY_EXECUTED' });
    expect(await ledger.spent(mandateHash(m), 'EUR')).toBe(2_500);
  });
});

describe.skipIf(!redisEngine.ok)('Redis end to end: a released reservation frees the key', () => {
  it('lets the retry run once the reservation is reconciled as not executed', async () => {
    const prefix = `e2e-${randomUUID()}`;
    const ledger = new RedisSpendingLedger(fromIoredis(io!), { prefix });
    const idempotency = new RedisIdempotencyStore(fromIoredis(io!), { prefix, leaseSeconds: 0.2 });
    const m = mandate();
    const chain = await chainFor(m);
    const opts = options({ ledger, idempotency });
    const p = { value: 900, idem: newIdempotencyKey() };
    const first = allow(await verify(chain, await payment(chain, m, p), opts, p));
    await sleep(300);
    expect(await verify(chain, await payment(chain, m, p), opts, p)).toMatchObject({ code: 'IDEMPOTENCY_UNRESOLVED' });
    await ledger.reconcile(first.reservation!, 'not_executed');
    const again = allow(await verify(chain, await payment(chain, m, p), opts, p));
    expect(again.idempotency!.attempt).not.toBe(first.idempotency!.attempt);
  });
});
