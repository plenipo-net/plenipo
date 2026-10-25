/**
 * Regression tests for the ops review of the shared stores (from the review PoC, now asserting the safe
 * behaviour):
 * - OPS-ST-1: request sessions keep `mandate` and `extraQueries` through Postgres and Redis, so legal-person
 *   and TS12 e-mandate requests complete across instances; stored values are revalidated on load.
 * - OPS-ST-2: a reservation whose outcome is unknown (here: the payment ran, the commit failed) stays
 *   counted after the expiry sweep; only an explicit reconciliation gives an amount back.
 * - OPS-NONCE-1: nonce and session stores expose their retention.
 * - P2-7 (second review): reconciliation also corrects under-counting. A commit or reconcile('executed')
 *   after a release (4xx after acting, or a reconciliation that looked too early) counts the amount again;
 *   legacy 'expired' rows are on the reconciliation list.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import pg from 'pg';
import { Redis } from 'ioredis';
import {
  createMandate,
  createMandateRequest,
  generateAgentKey,
  handleMandateResponse,
  InMemoryNonceStore,
  nowSeconds,
  type AgentKey,
  type Mandate,
  type MandateRequest,
  type StatusFetcher,
} from '../src/index.js';
import {
  createLegalMandate,
} from '../src/experimental.js';
import {
  createPostgresResponseSessionStore,
  createRedisResponseSessionStore,
  deserializeSession,
  fromIoredis,
  migratePostgres,
  PostgresMandateSessionStore,
  PostgresNonceStore,
  PostgresSpendingLedger,
  RedisMandateSessionStore,
  RedisNonceStore,
  RedisSpendingLedger,
  serializeSession,
  type MandateSessionStore,
} from '../src/stores/index.js';
import {
  createTestPidProvider,
  createTestRegister,
  createTestScaIssuer,
  createTestWallet,
  TEST_SCA_VCT,
  type TestAttestationIssuer,
  type TestPidProvider,
  type TestRegister,
  type TestWallet,
} from '../src/testing.js';
import { startPostgres, startRedis } from './stores-engines.js';

const pgEngine = await startPostgres();
const redisEngine = await startRedis();
const CLIENT_ID = 'x509_san_dns:agents.example';
const EUID = 'ITRM.RM1234567';
const DAY = 24 * 3600;

let agent: AgentKey;
let provider: TestPidProvider;
let bank: TestAttestationIssuer & { transactionDataTypes: string[] };
let register: TestRegister;
let director: TestWallet;
let statusFetcher: StatusFetcher;
let pool: pg.Pool | undefined;
let redis: Redis | undefined;
const stores: Array<[string, () => MandateSessionStore]> = [];

beforeAll(async () => {
  agent = await generateAgentKey();
  provider = await createTestPidProvider('https://pid.test');
  bank = await createTestScaIssuer('https://bank.test', { statusList: true });
  register = await createTestRegister('https://register.test');
  statusFetcher = async (uri) => {
    for (const i of [bank, register]) if (uri.startsWith(`${i.iss}/`)) return i.statusFetcher(uri);
    throw new Error('unknown status list');
  };
  director = await createTestWallet();
  director.storePid(await provider.issuePid(director.holderJwk, { given_name: 'Mario', family_name: 'Rossi', birthdate: '1980-01-01' }));
  director.storeCredential(await bank.issue(director.holderJwk, { iban: 'IT60X0542811101000000123456' }), { transactionDataTypes: bank.transactionDataTypes });
  director.storeCredential(
    await register.issueRepresentation(director.holderJwk, {
      legal_person_id: EUID,
      legal_person_name: 'Acme S.p.A.',
      representative: { given_name: 'Mario', family_name: 'Rossi' },
      role: { code: 'managing_director', name: 'Amministratore delegato', basis: 'legal_representation', valid_until: nowSeconds() + 180 * DAY },
      powers: { actions: ['payments.*'], limits: { currency: 'EUR', per_operation: 100000, total: 500000 }, max_delegation_depth: 2 },
    } as any),
  );
  if (pgEngine.ok) {
    pool = new pg.Pool({ connectionString: pgEngine.url });
    await migratePostgres(pool, { tablePrefix: 'regops_' });
    stores.push(['Postgres', () => new PostgresMandateSessionStore(pool!, { tablePrefix: 'regops_' })]);
  }
  if (redisEngine.ok) {
    redis = new Redis(redisEngine.url);
    stores.push(['Redis', () => new RedisMandateSessionStore(fromIoredis(redis!), { prefix: 'regops' })]);
  }
});

afterAll(async () => {
  await pool?.end();
  redis?.disconnect();
  if (pgEngine.ok) await pgEngine.stop();
  if (redisEngine.ok) await redisEngine.stop();
});

function legalMandate(): Mandate {
  return createLegalMandate({
    agentJwk: agent.publicJwk,
    actions: ['payments.sepa'],
    counterparties: ['shop.example'],
    limits: { currency: 'EUR', per_operation: 15000, total: 30000 },
    principal: { type: 'legal_person', euid: EUID, role: 'managing_director' } as any,
  });
}

function plainMandate(): Mandate {
  return createMandate({
    agentJwk: agent.publicJwk,
    actions: ['payments.sepa'],
    counterparties: ['shop.example'],
    limits: { currency: 'EUR', per_operation: 15000, total: 30000 },
  });
}

const responseOptions = () => ({
  trustedIssuers: [provider.trusted],
  now: nowSeconds(),
  sessions: new InMemoryNonceStore(),
  statusFetcher,
  emandate: { scaTrust: { trustedIssuers: [bank.trusted] }, scaVcts: [TEST_SCA_VCT] },
  representation: { trust: { trustedIssuers: [register.trusted] } },
});

const cases: Array<[string, () => Promise<MandateRequest>]> = [
  ['legal person (representation attestation)', async () => createMandateRequest({ mandate: legalMandate(), clientId: CLIENT_ID, responseUri: 'https://agents.example/vp/1' })],
  [
    'TS12 e-mandate bound to an SCA attestation',
    async () =>
      createMandateRequest({
        mandate: plainMandate(),
        clientId: CLIENT_ID,
        responseUri: 'https://agents.example/vp/2',
        transactionDataType: 'emandate',
        emandate: { scaVcts: [TEST_SCA_VCT] },
      }),
  ],
];

describe.skipIf(!pgEngine.ok || !redisEngine.ok)('OPS-ST-1: shared request session stores keep mandate and extraQueries', () => {
  for (const [label, make] of cases) {
    it(`${label}: the response is accepted after a store round trip`, async () => {
      for (const [engine, store] of stores) {
        const req = await make();
        const body = await director.respond(req.params);
        const id = `req-${Math.random().toString(36).slice(2)}`;
        const s = store();
        await s.put(id, req.session);
        // Another instance loads the session and handles the wallet's answer.
        const loaded = (await store().get(id))!;
        expect(req.session.extraQueries ?? req.session.mandate, engine).toBeDefined();
        expect(loaded.extraQueries, engine).toEqual(req.session.extraQueries);
        expect(loaded.mandate, engine).toEqual(req.session.mandate);
        await expect(handleMandateResponse(body, loaded, responseOptions()), engine).resolves.toBeDefined();
      }
    });
  }

  it('revalidates stored mandate and extraQueries, and still reads the previous format', async () => {
    const req = await cases[1][1]();
    const text = await serializeSession(req.session);
    const parsed = JSON.parse(text);
    expect(parsed.v).toBe(2);
    expect((await deserializeSession(text)).mandate).toEqual(req.session.mandate);

    const tamper = (f: (x: any) => void) => {
      const x = JSON.parse(text);
      f(x);
      return deserializeSession(JSON.stringify(x));
    };
    await expect(tamper((x) => (x.extraQueries = ['sca', 'admin']))).rejects.toThrow(/unknown query id/);
    await expect(tamper((x) => (x.extraQueries = ['sca', 'sca']))).rejects.toThrow(/distinct/);
    await expect(tamper((x) => (x.extraQueries = 'sca'))).rejects.toThrow();
    await expect(tamper((x) => (x.mandate.id = 'another-mandate-id'))).rejects.toThrow(/not the requested mandate/);
    await expect(tamper((x) => (x.mandate.agent.jwk.d = 'secret'))).rejects.toThrow(/invalid/);
    await expect(tamper((x) => (x.mandate.limits.total = -1))).rejects.toThrow(/invalid/);
    await expect(tamper((x) => (x.mandate.principal = { type: 'legal_person', euid: 'nope' }))).rejects.toThrow(/invalid/);
    await expect(tamper((x) => (x.v = 3))).rejects.toThrow(/shape/);
    // Version 1 cannot carry the new members.
    await expect(tamper((x) => (x.v = 1))).rejects.toThrow(/version/);

    // A session written in version 1 (before e-mandates) still loads.
    const plain = await createMandateRequest({ mandate: plainMandate(), clientId: CLIENT_ID, responseUri: 'https://agents.example/vp/3' });
    const v1 = JSON.parse(await serializeSession(plain.session));
    v1.v = 1;
    const back = await deserializeSession(JSON.stringify(v1));
    expect(back.state).toBe(plain.session.state);
    expect(back.mandate).toBeUndefined();
    expect(back.extraQueries).toBeUndefined();
  });
});

describe.skipIf(!pgEngine.ok)('OPS-ST-2: a reservation with an unknown outcome stays spent after the sweep', () => {
  it('payment executed, commit failed once, the sweep keeps the amount counted until reconciled', async () => {
    const { createGateway, createInvocation, authorizationHeaders, mandateHash } = await import('../src/index.js');
    const real = new PostgresSpendingLedger(pool!, { tablePrefix: 'regops_', pendingTtlSeconds: 0.5 });
    let failCommit = true;
    const ledger = Object.assign(Object.create(real), {
      async commit(id: string) {
        if (failCommit) {
          failCommit = false;
          throw new Error('canceling statement due to statement timeout'); // transient DB error
        }
        return real.commit(id);
      },
    }) as typeof real;
    const errors: string[] = [];
    const executed: number[] = [];
    const API = 'https://api.bank.example';
    const gw = createGateway({
      routes: [{ method: 'POST', path: '/pay', action: 'payments.sepa', counterparty: (r) => (r.json() as any).creditor, amount: (r) => ({ value: (r.json() as any).amount, currency: 'EUR' }) }],
      verify: { audience: API, nonces: new InMemoryNonceStore(), ledger, trustedIssuers: [provider.trusted] },
      onError: (e, phase) => errors.push(phase),
      async downstream(req) {
        executed.push(((await req.json()) as any).amount);
        return new Response(null, { status: 201 });
      },
    });
    const m = plainMandate(); // total 30000
    const chain = { root: await director.approveMandate(m), delegations: [] };
    const body = { creditor: 'shop.example', amount: 15000 };
    const inv = await createInvocation(agent.privateKey, {
      chain,
      mandateId: m.id, action: 'payments.sepa', counterparty: 'shop.example', amount: { value: 15000, currency: 'EUR' }, aud: API,
      args: { method: 'POST', path: '/pay', query: {}, media_type: 'application/json', body },
    });
    const res = await gw.handle(new Request(API + '/pay', { method: 'POST', headers: { ...authorizationHeaders(chain, inv), 'content-type': 'application/json' }, body: JSON.stringify(body) }));
    expect(res.status).toBe(201);
    expect(errors).toEqual(['commit']);
    const key = mandateHash(m);
    expect(await real.spent(key, 'EUR')).toBe(15000);
    await new Promise((r) => setTimeout(r, 700));
    expect(await real.sweepExpired()).toBe(1);
    // The executed payment still counts: the agent cannot spend more than the total.
    expect(await real.spent(key, 'EUR')).toBe(15000);
    expect(await real.reserve([{ key, total: 30000 }], { value: 15001, currency: 'EUR' })).toBeNull();
    const [stuck] = await real.unresolved();
    expect(stuck).toMatchObject({ state: 'expired_spent', amount: 15000 });
    // A blind release cannot undo it; a reconciliation that finds the payment confirms it.
    await real.release(stuck.id);
    expect(await real.spent(key, 'EUR')).toBe(15000);
    expect(await real.reconcile(stuck.id, 'executed')).toBe('committed');
    expect(await real.reconcile(stuck.id, 'not_executed')).toBe('committed');
    expect(await real.spent(key, 'EUR')).toBe(15000);
    expect(executed).toEqual([15000]);
  });

  it('behaves the same on Redis', async () => {
    if (!redisEngine.ok) return;
    const l = new RedisSpendingLedger(fromIoredis(redis!), { prefix: `regops-${Math.random()}`, pendingTtlSeconds: 0.2 });
    const id = (await l.reserve([{ key: 'k', total: 100 }], { value: 60, currency: 'EUR' }))!;
    await new Promise((r) => setTimeout(r, 300));
    expect(await l.sweepExpired()).toBe(1);
    expect(await l.spent('k', 'EUR')).toBe(60);
    await l.release(id);
    expect(await l.spent('k', 'EUR')).toBe(60);
    expect(await l.reconcile(id, 'not_executed')).toBe('released');
    expect(await l.spent('k', 'EUR')).toBe(0);
  });
});

describe('OPS-NONCE-1: stores expose their retention', () => {
  it('reports retentionSeconds on nonce and session stores', () => {
    expect(new InMemoryNonceStore().retentionSeconds).toBe(Infinity);
    const fake = { query: async () => ({ rows: [] }) };
    const fakeRedis = { eval: async () => null, evalsha: async () => null, setNxPx: async () => null };
    expect(new PostgresNonceStore(fake, { retentionSeconds: 240 }).retentionSeconds).toBe(240);
    expect(new PostgresNonceStore(fake).retentionSeconds).toBe(600);
    expect(new RedisNonceStore(fakeRedis, { retentionSeconds: 180 }).retentionSeconds).toBe(180);
    expect(createPostgresResponseSessionStore(fake).retentionSeconds).toBe(660);
    expect(createRedisResponseSessionStore(fakeRedis, { maxAgeSeconds: 300 }).retentionSeconds).toBe(360);
    expect(new PostgresMandateSessionStore(fake, { ttlSeconds: 120 }).retentionSeconds).toBe(120);
    expect(new RedisMandateSessionStore(fakeRedis).retentionSeconds).toBe(600);
  });
});

describe('P2-7: late evidence of execution corrects a release', () => {
  type L = PostgresSpendingLedger | RedisSpendingLedger;
  const engines: Array<[string, () => L, boolean]> = [
    ['Postgres', () => new PostgresSpendingLedger(pool!, { tablePrefix: 'regops_', pendingTtlSeconds: 0.3 }), pgEngine.ok],
    ['Redis', () => new RedisSpendingLedger(fromIoredis(redis!), { prefix: `p27-${Math.random()}`, pendingTtlSeconds: 0.3 }), redisEngine.ok],
  ];
  for (const [name, make, ok] of engines) {
    it.skipIf(!ok)(`${name}: released (4xx after acting), then reconcile executed: counted, and the total holds`, async () => {
      const l = make();
      const key = `k-${Math.random()}`;
      const id = (await l.reserve([{ key, total: 100_000 }], { value: 60_000, currency: 'EUR' }))!;
      await l.release(id); // gateway: the API answered 409 after booking the payment
      expect(await l.reconcile(id, 'executed')).toBe('committed'); // the back office finds it on the rail
      expect(await l.reconcile(id, 'executed')).toBe('committed');
      expect(await l.spent(key, 'EUR')).toBe(60_000);
      expect(await l.reserve([{ key, total: 100_000 }], { value: 60_000, currency: 'EUR' })).toBeNull();
      expect(await l.reservation(id)).toMatchObject({ state: 'committed', releasedBy: 'release' });
      expect((await l.reservation(id))?.correctedAt).toBeInstanceOf(Date);
    });

    it.skipIf(!ok)(`${name}: reconcile not_executed (too early), then the late commit: counted`, async () => {
      const l = make();
      const key = `k-${Math.random()}`;
      const id = (await l.reserve([{ key, total: 100_000 }], { value: 60_000, currency: 'EUR' }))!;
      await new Promise((r) => setTimeout(r, 400));
      expect(await l.sweepExpired()).toBeGreaterThanOrEqual(1);
      expect(await l.reconcile(id, 'not_executed')).toBe('released');
      expect(await l.spent(key, 'EUR')).toBe(0);
      expect(await l.settle(id, 'commit')).toBe('committed'); // the gateway's commit arrives: the action did run
      expect(await l.settle(id, 'commit')).toBe('committed');
      expect(await l.spent(key, 'EUR')).toBe(60_000);
      expect(await l.reservation(id)).toMatchObject({ state: 'committed', releasedBy: 'reconcile' });
    });
  }

  it.skipIf(!redisEngine.ok)('Redis: legacy expired reservations are adopted onto the reconciliation list', async () => {
    const prefix = `legacy-${Math.random()}`;
    const l = new RedisSpendingLedger(fromIoredis(redis!), { prefix });
    const id = crypto.randomUUID();
    const key = `{${prefix}:ledger}:res:${id}`;
    // What a version 1 sweep left behind: amount given back, state 'expired', a TTL.
    await redis!.hset(key, { state: 'expired', currency: 'EUR', amount: '70', keys: '["EUR:k"]', created: '1', expires: '2', settled: '3' });
    await redis!.pexpire(key, 60_000);
    expect(await l.unresolved()).toEqual([]);
    expect(await l.adoptLegacyExpired({ count: 10 })).toBe(1);
    expect(await l.adoptLegacyExpired()).toBe(1); // idempotent: re-adding the same id changes nothing
    expect(await redis!.pttl(key)).toBe(-1);
    expect((await l.unresolved()).map((r) => r.id)).toEqual([id]);
    expect(await l.reconcile(id, 'executed')).toBe('committed');
    expect(await l.spent('k', 'EUR')).toBe(70);
    expect(await l.unresolved()).toEqual([]);
  });
});
