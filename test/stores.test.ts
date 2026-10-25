/**
 * Shared stores against real engines: a throwaway Postgres cluster, a throwaway redis-server, and
 * PGlite for driver compatibility. Every concurrency test runs its operations through two separate
 * clients (two pg pools; an ioredis and a node-redis connection), as two verifier replicas would.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import pg from 'pg';
import { Redis } from 'ioredis';
import { createClient } from 'redis';
import { PGlite } from '@electric-sql/pglite';
import {
  createInvocation,
  createMandate,
  createMandateRequest,
  delegateMandate,
  generateAgentKey,
  handleMandateResponse,
  mandateHash,
  nowSeconds,
  verifyAuthorization,
  type AgentKey,
  type Mandate,
  type MandateChain,
  type NonceStore,
  type SpendingLedger,
} from '../src/index.js';
import {
  createPostgresResponseSessionStore,
  createRedisResponseSessionStore,
  fromIoredis,
  fromNodeRedis,
  migratePostgres,
  nonceRetentionSeconds,
  postgresSchema,
  POSTGRES_SCHEMA_SQL,
  PostgresMandateSessionStore,
  PostgresNonceStore,
  PostgresRevocationRegistry,
  PostgresSpendingLedger,
  RedisMandateSessionStore,
  RedisNonceStore,
  RedisRevocationRegistry,
  RedisSpendingLedger,
  type ManagedRevocationRegistry,
  type MandateSessionStore,
  type ReservationInfo,
  type SqlClient,
} from '../src/stores/index.js';
import type { LedgerEntry } from '../src/registry.js';
import { createTestPidProvider, createTestWallet, type TestPidProvider, type TestWallet } from '../src/testing.js';
import { startPostgres, startRedis } from './stores-engines.js';

const pgEngine = await startPostgres();
const redisEngine = await startRedis();
// The reason goes into the suite name too, so every reporter shows why the tests were skipped.
const pgLabel = pgEngine.ok ? 'Postgres' : `Postgres (skipped: ${pgEngine.reason})`;
const redisLabel = redisEngine.ok ? 'Redis' : `Redis (skipped: ${redisEngine.reason})`;
if (!pgEngine.ok) console.warn(`[stores] skipping Postgres tests: ${pgEngine.reason}`);
if (!redisEngine.ok) console.warn(`[stores] skipping Redis tests: ${redisEngine.reason}`);

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const EUR = (value: number) => ({ value, currency: 'EUR' });
const uniq = (label: string) => `${label}-${randomUUID()}`;

type SharedLedger = SpendingLedger & {
  spent(key: string, currency: string): Promise<number>;
  reserve(entries: LedgerEntry[], amount: { value: number; currency: string }): Promise<string | null>;
  settle(id: string, action: 'commit' | 'release'): Promise<string>;
  sweepExpired(opts?: { limit?: number }): Promise<number>;
  reconcile(id: string, outcome: 'executed' | 'not_executed'): Promise<string>;
  unresolved(opts?: { limit?: number }): Promise<ReservationInfo[]>;
  reservation(id: string): Promise<ReservationInfo | undefined>;
};

/** One storage engine, seen through two independent connections. Each call gets a fresh namespace. */
interface Backend {
  ledgers(opts?: { pendingTtlSeconds?: number }): Promise<[SharedLedger, SharedLedger]>;
  nonces(opts?: { retentionSeconds?: number; namespace?: string }): Promise<[NonceStore, NonceStore]>;
  responseSessions(): Promise<[NonceStore, NonceStore]>;
  requestSessions(opts?: { ttlSeconds?: number }): Promise<[MandateSessionStore, MandateSessionStore]>;
  revocations(): Promise<[ManagedRevocationRegistry, ManagedRevocationRegistry]>;
}

// ---------------------------------------------------------------- shared fixtures for end-to-end tests

const AUD = 'https://bank.example';
const CLIENT_ID = 'x509_san_dns:agents.example';
let provider: TestPidProvider;
let wallet: TestWallet;
let agent: AgentKey;
let subAgent: AgentKey;

beforeAll(async () => {
  provider = await createTestPidProvider('https://pid-stores.example');
  wallet = await createTestWallet();
  wallet.storePid(await provider.issuePid(wallet.holderJwk, { given_name: 'Ada', family_name: 'Lovelace' }));
  agent = await generateAgentKey();
  subAgent = await generateAgentKey();
});

async function delegatedChain(rootTotal: number, childTotal: number): Promise<{ parent: Mandate; child: Mandate; chain: MandateChain }> {
  const parent = createMandate({
    agentJwk: agent.publicJwk,
    actions: ['payments.*'],
    counterparties: ['shop.example'],
    limits: { currency: 'EUR', per_operation: 100_000, total: rootTotal },
    maxDepth: 1,
  });
  const child = createMandate({
    agentJwk: subAgent.publicJwk,
    actions: ['payments.transfer'],
    counterparties: ['shop.example'],
    limits: { currency: 'EUR', per_operation: 100_000, total: childTotal },
    nbf: parent.nbf,
    exp: parent.exp - 60,
  });
  const jws = await delegateMandate({ parent, parentAgentKey: agent.privateKey, child });
  return { parent, child, chain: { root: await wallet.approveMandate(parent), delegations: [jws] } };
}

function pay(chain: MandateChain, child: Mandate, value: number, nonce?: string): Promise<string> {
  return createInvocation(subAgent.privateKey, { chain,
    mandateId: child.id,
    action: 'payments.transfer',
    counterparty: 'shop.example',
    amount: EUR(value),
    aud: AUD,
    ...(nonce ? { nonce } : {}),
  });
}

// ---------------------------------------------------------------- the contract every backend must meet

function contract(name: string, enabled: boolean, backend: () => Backend) {
  describe.skipIf(!enabled)(`${name}: spending ledger`, () => {
    it('lets exactly k of 50 parallel reserves through, across two connections', async () => {
      const [a, b] = await backend().ledgers();
      const key = uniq('k');
      // 1000 / 70 = 14 reservations fit.
      const results = await Promise.all(
        Array.from({ length: 50 }, (_, i) => (i % 2 ? a : b).reserve([{ key, total: 1000 }], EUR(70))),
      );
      expect(results.filter((r) => r !== null)).toHaveLength(14);
      expect(new Set(results.filter((r) => r !== null)).size).toBe(14);
      expect(await a.spent(key, 'EUR')).toBe(980);
      expect(await b.spent(key, 'EUR')).toBe(980);
    });

    it('checks every entry of the chain: exactly k pass when the tightest total is in the middle', async () => {
      const [a, b] = await backend().ledgers();
      const [root, mid, leaf] = [uniq('root'), uniq('mid'), uniq('leaf')];
      const chain = [
        { key: root, total: 10_000 },
        { key: mid, total: 500 },
        { key: leaf },
      ];
      const results = await Promise.all(
        Array.from({ length: 40 }, (_, i) => (i % 2 ? a : b).reserve(i % 3 ? chain : [...chain].reverse(), EUR(60))),
      );
      expect(results.filter((r) => r !== null)).toHaveLength(8);
      for (const k of [root, mid, leaf]) expect(await a.spent(k, 'EUR')).toBe(480);
    });

    it('never deadlocks when parallel chains list the same mandates in opposite orders', async () => {
      const [a, b] = await backend().ledgers();
      const ks = Array.from({ length: 4 }, (_, i) => ({ key: uniq(`d${i}`), total: 1_000_000 }));
      const orders = [ks, [...ks].reverse(), [ks[2], ks[0], ks[3], ks[1]], [ks[1], ks[3], ks[0], ks[2]]];
      const ids = await Promise.all(Array.from({ length: 160 }, (_, i) => (i % 2 ? a : b).reserve(orders[i % 4], EUR(1))));
      expect(ids.every((id) => id !== null)).toBe(true);
      await Promise.all(ids.map((id, i) => (i % 3 ? a.release(id!) : b.commit(id!))));
      for (const k of ks) expect(await a.spent(k.key, 'EUR')).toBe(ids.filter((_, i) => i % 3 === 0).length);
    });

    it('changes nothing when one entry is full (multi-entry atomicity)', async () => {
      const [a, b] = await backend().ledgers();
      const [wide, full] = [uniq('wide'), uniq('full')];
      const filler = await a.reserve([{ key: full, total: 100 }], EUR(100));
      await a.commit(filler!);
      const r = await b.reserve(
        [
          { key: wide, total: 1000 },
          { key: full, total: 100 },
        ],
        EUR(50),
      );
      expect(r).toBeNull();
      expect(await a.spent(wide, 'EUR')).toBe(0);
      expect(await a.spent(full, 'EUR')).toBe(100);
      // The other order, and from the other connection: same outcome.
      expect(await a.reserve([{ key: full, total: 100 }, { key: wide, total: 1000 }], EUR(1))).toBeNull();
      expect(await b.spent(wide, 'EUR')).toBe(0);
    });

    it('keeps currencies apart', async () => {
      const [a] = await backend().ledgers();
      const key = uniq('k');
      expect(await a.reserve([{ key, total: 100 }], EUR(100))).not.toBeNull();
      expect(await a.reserve([{ key, total: 100 }], { value: 100, currency: 'USD' })).not.toBeNull();
      expect(await a.spent(key, 'EUR')).toBe(100);
      expect(await a.spent(key, 'USD')).toBe(100);
    });

    it('counts a key listed twice once, against the tighter total', async () => {
      const [a] = await backend().ledgers();
      const key = uniq('dup');
      expect(await a.reserve([{ key, total: 1000 }, { key, total: 100 }], EUR(101))).toBeNull();
      expect(await a.reserve([{ key, total: 1000 }, { key, total: 100 }], EUR(100))).not.toBeNull();
      expect(await a.spent(key, 'EUR')).toBe(100);
    });

    it('makes commit and release idempotent, and ignores unknown or foreign ids', async () => {
      const [a, b] = await backend().ledgers();
      const key = uniq('k');
      const e = [{ key, total: 1000 }];

      const r1 = (await a.reserve(e, EUR(300)))!;
      await a.commit(r1);
      await b.commit(r1);
      await b.release(r1); // release of a committed reservation: no-op
      expect(await a.spent(key, 'EUR')).toBe(300);
      expect((await b.reservation(r1))?.state).toBe('committed');

      const r2 = (await b.reserve(e, EUR(200)))!;
      expect(await a.spent(key, 'EUR')).toBe(500);
      await a.release(r2);
      await b.release(r2);
      expect(await a.spent(key, 'EUR')).toBe(300);
      expect((await a.reservation(r2))?.state).toBe('released');
      // Changed with P2-7: a commit after a release is evidence the action ran, and corrects it (once).
      await a.commit(r2);
      await b.commit(r2);
      await a.release(r2);
      expect(await a.spent(key, 'EUR')).toBe(500);
      expect(await a.reservation(r2)).toMatchObject({ state: 'committed', releasedBy: 'release' });
      expect((await a.reservation(r2))?.correctedAt).toBeInstanceOf(Date);

      for (const bogus of [randomUUID(), 'not-a-uuid', '', "x'; DROP TABLE x; --", 'A'.repeat(10_000)]) {
        await a.release(bogus);
        await a.commit(bogus);
      }
      expect(await a.spent(key, 'EUR')).toBe(500);
    });

    it('counts a reservation once when commit and release race from two replicas: the commit wins', async () => {
      const [a, b] = await backend().ledgers();
      const key = uniq('k');
      const ids = await Promise.all(Array.from({ length: 20 }, () => a.reserve([{ key, total: 100_000 }], EUR(10))));
      await Promise.all(ids.flatMap((id, i) => [i % 2 ? a.commit(id!) : a.release(id!), i % 2 ? b.release(id!) : b.commit(id!), a.release(id!)]));
      const states = await Promise.all(ids.map(async (id) => (await a.reservation(id!))!.state));
      expect(states.every((s) => s === 'committed')).toBe(true);
      expect(await b.spent(key, 'EUR')).toBe(200);
    });

    it('corrects releases with late evidence of execution, once, even beyond a total', async () => {
      const [a, b] = await backend().ledgers();
      const key = uniq('k');
      const e = [{ key, total: 100 }];
      const first = (await a.reserve(e, EUR(100)))!;
      await a.release(first); // e.g. the API answered 4xx after acting
      const second = (await b.reserve(e, EUR(100)))!;
      await b.commit(second);
      // The back office finds the first payment on the rail: spending is 200 against a total of 100, the truth.
      const results = await Promise.all([a.reconcile(first, 'executed'), b.reconcile(first, 'executed'), a.commit(first), b.commit(first), b.release(first)]);
      expect(results[0]).toBe('committed');
      expect(await a.spent(key, 'EUR')).toBe(200);
      expect(await a.reservation(first)).toMatchObject({ state: 'committed', releasedBy: 'release' });
      expect(await b.reserve(e, EUR(0))).toBeNull();
      expect(await a.reconcile(first, 'not_executed')).toBe('committed');

      // Many released reservations corrected concurrently from two replicas are each counted once.
      const big = uniq('big');
      const ids = (await Promise.all(Array.from({ length: 20 }, () => a.reserve([{ key: big, total: 1000 }], EUR(10))))).map((x) => x!);
      await Promise.all(ids.map((id, i) => (i % 2 ? a : b).release(id)));
      expect(await a.spent(big, 'EUR')).toBe(0);
      await Promise.all(ids.flatMap((id) => [a.commit(id), b.reconcile(id, 'executed'), b.commit(id), a.release(id), a.reconcile(id, 'not_executed')]));
      expect(await b.spent(big, 'EUR')).toBe(200);
      for (const id of ids) expect((await a.reservation(id))?.state).toBe('committed');
    });

    it('rejects malformed amounts and entries without recording anything', async () => {
      const [a] = await backend().ledgers();
      const key = uniq('k');
      const bad: Array<[LedgerEntry[], unknown]> = [
        [[{ key, total: 1000 }], EUR(-1)],
        [[{ key, total: 1000 }], EUR(1.5)],
        [[{ key, total: 1000 }], EUR(Number.NaN)],
        [[{ key, total: 1000 }], EUR(Number.MAX_SAFE_INTEGER + 1)],
        [[{ key, total: 1000 }], { value: '10', currency: 'EUR' }],
        [[{ key, total: 1000 }], { value: 10, currency: 'eur' }],
        [[{ key, total: 1000 }], { value: 10, currency: "EUR'--" }],
        [[{ key, total: 1000 }], null],
        [[], EUR(10)],
        [Array.from({ length: 100 }, (_, i) => ({ key: `${key}-${i}` })), EUR(10)],
        [[{ key: '' }], EUR(10)],
        [[{ key: 'k'.repeat(1000) }], EUR(10)],
        [[{ key, total: -5 }], EUR(10)],
        [[{ key, total: 2.5 }], EUR(1)],
        [[{ key: 42 as unknown as string }], EUR(1)],
      ];
      for (const [entries, amount] of bad) {
        await expect(a.reserve(entries, amount as { value: number; currency: string })).rejects.toThrow();
      }
      expect(await a.spent(key, 'EUR')).toBe(0);
      await expect(a.spent(key, 'euro')).rejects.toThrow();
    });

    it('never overspends or deadlocks under random overlapping chains, commits and releases', async () => {
      const [a, b] = await backend().ledgers();
      const keys = Array.from({ length: 5 }, (_, i) => ({ key: uniq(`s${i}`), total: 400 + i * 100 }));
      type Rec = { id: string; keys: string[]; amount: number };
      const recs: Rec[] = [];
      let denied = 0;
      let seed = 42;
      const rand = (n: number) => {
        seed = (seed * 1103515245 + 12345) % 2 ** 31;
        return seed % n;
      };
      const plans = Array.from({ length: 240 }, () => {
        const shuffled = [...keys].sort(() => rand(3) - 1);
        return { entries: shuffled.slice(0, 1 + rand(4)), amount: 1 + rand(40), settle: rand(4), via: rand(2) };
      });
      await Promise.all(
        plans.map(async (p, i) => {
          const l = i % 2 ? a : b;
          const id = await l.reserve(p.entries, EUR(p.amount));
          if (id === null) {
            denied++;
            return;
          }
          recs.push({ id, keys: p.entries.map((e) => e.key), amount: p.amount });
          const other = p.via ? a : b;
          if (p.settle === 0) await other.commit(id);
          else if (p.settle === 1) await other.release(id);
          else if (p.settle === 2) await Promise.all([a.commit(id), b.commit(id), a.release(id)]);
          // settle === 3: left pending
        }),
      );
      expect(denied).toBeGreaterThan(0);
      const states = new Map(await Promise.all(recs.map(async (r) => [r.id, (await a.reservation(r.id))!.state] as const)));
      for (const k of keys) {
        const expected = recs
          .filter((r) => r.keys.includes(k.key) && states.get(r.id) !== 'released')
          .reduce((s, r) => s + r.amount, 0);
        const spent = await b.spent(k.key, 'EUR');
        expect(spent).toBe(expected);
        expect(spent).toBeLessThanOrEqual(k.total);
      }
    });

    // Changed with OPS-ST-2: the sweep used to give stale amounts back ('expired'); it now counts them
    // as spent ('expired_spent') until a reconciliation says the action did not run.
    it('counts stale pending reservations as spent: a sweep never gives an amount back', async () => {
      const [a, b] = await backend().ledgers({ pendingTtlSeconds: 0.3 });
      const key = uniq('k');
      const stale = (await a.reserve([{ key, total: 1000 }], EUR(400)))!;
      const abandoned = (await a.reserve([{ key, total: 1000 }], EUR(100)))!;
      await sleep(450);
      const fresh = (await b.reserve([{ key, total: 1000 }], EUR(50)))!;
      expect(await a.spent(key, 'EUR')).toBe(550);

      // Two replicas sweeping at once expire each reservation once, and the totals do not move.
      const swept = await Promise.all([a.sweepExpired(), b.sweepExpired()]);
      expect(swept[0] + swept[1]).toBe(2);
      expect(await a.sweepExpired()).toBe(0);
      expect(await a.spent(key, 'EUR')).toBe(550);
      expect((await a.reservation(stale))?.state).toBe('expired_spent');
      expect((await a.reservation(fresh))?.state).toBe('pending');
      // The budget the stuck reservations hold stays unavailable.
      expect(await b.reserve([{ key, total: 1000 }], EUR(451))).toBeNull();

      // A plain release (what a gateway calls when it believes the action did not run) cannot give it back.
      await a.release(abandoned);
      await b.release(abandoned);
      expect((await a.reservation(abandoned))?.state).toBe('expired_spent');
      expect(await a.spent(key, 'EUR')).toBe(550);

      // A late commit confirms the spending without counting it twice.
      await b.commit(stale);
      await a.commit(stale);
      expect((await a.reservation(stale))?.state).toBe('committed');
      expect(await a.spent(key, 'EUR')).toBe(550);
      expect((await a.unresolved()).map((r) => r.id)).toEqual([abandoned]);
    });

    it('gives an amount back only through an explicit reconciliation, never for a committed reservation', async () => {
      const [a, b] = await backend().ledgers({ pendingTtlSeconds: 0.3 });
      const key = uniq('k');
      const e = [{ key, total: 1000 }];
      const lost = (await a.reserve(e, EUR(300)))!; // will expire, then be reconciled as not executed
      const paid = (await a.reserve(e, EUR(200)))!; // will expire, then be reconciled as executed
      await sleep(450);
      const pending = (await b.reserve(e, EUR(100)))!; // reconciled while still pending
      const done = (await b.reserve(e, EUR(50)))!;
      await b.commit(done);
      expect(await a.sweepExpired()).toBe(2);
      expect((await b.unresolved()).map((r) => r.id).sort()).toEqual([lost, paid].sort());
      expect(await a.spent(key, 'EUR')).toBe(650);

      // Racing reconciliations from two replicas apply once.
      const [r1, r2] = await Promise.all([a.reconcile(lost, 'not_executed'), b.reconcile(lost, 'not_executed')]);
      expect([r1, r2]).toEqual(['released', 'released']);
      expect(await a.spent(key, 'EUR')).toBe(350);
      expect(await a.reconcile(paid, 'executed')).toBe('committed');
      expect(await a.spent(key, 'EUR')).toBe(350);
      expect(await b.reconcile(pending, 'not_executed')).toBe('released');
      expect(await a.spent(key, 'EUR')).toBe(250);

      // Committed money is never given back.
      expect(await a.reconcile(done, 'not_executed')).toBe('committed');
      expect(await a.reconcile(paid, 'not_executed')).toBe('committed');
      expect(await a.spent(key, 'EUR')).toBe(250);
      expect(await a.unresolved()).toEqual([]);
      expect(await a.reservation(lost)).toMatchObject({ state: 'released', releasedBy: 'reconcile' });
      // Changed with P2-7: a reconciliation that looked too early is corrected by later evidence.
      expect(await b.commit(lost)).toBeUndefined();
      expect(await a.reservation(lost)).toMatchObject({ state: 'committed', releasedBy: 'reconcile' });
      expect(await a.spent(key, 'EUR')).toBe(550);

      expect(await a.reconcile(randomUUID(), 'not_executed')).toBe('unknown');
      expect(await a.reconcile('nope', 'not_executed')).toBe('unknown');
      await expect(a.reconcile(done, 'maybe' as 'executed')).rejects.toThrow();
    });

    it('settles each reservation once when sweeps race commits', async () => {
      const [a, b] = await backend().ledgers({ pendingTtlSeconds: 0.2 });
      const key = uniq('k');
      const ids = (await Promise.all(Array.from({ length: 30 }, () => a.reserve([{ key, total: 100_000 }], EUR(7))))).map((x) => x!);
      await sleep(300);
      await Promise.all([a.sweepExpired({ limit: 7 }), b.sweepExpired(), ...ids.map((id, i) => (i % 2 ? a : b).commit(id)), a.sweepExpired()]);
      for (const id of ids) expect((await a.reservation(id))?.state).toBe('committed');
      expect(await b.spent(key, 'EUR')).toBe(30 * 7);
    });
  });

  describe.skipIf(!enabled)(`${name}: nonces and sessions`, () => {
    it('consumes a nonce once across two connections, even when 30 race for it', async () => {
      const [a, b] = await backend().nonces();
      const n = uniq('nonce');
      expect(await a.consume(n)).toBe(true);
      expect(await b.consume(n)).toBe(false);
      expect(await a.consume(n)).toBe(false);
      const raced = uniq('raced');
      const results = await Promise.all(Array.from({ length: 30 }, (_, i) => (i % 2 ? a : b).consume(raced)));
      expect(results.filter(Boolean)).toHaveLength(1);
    });

    it('refuses nonces that are not usable strings', async () => {
      const [a] = await backend().nonces();
      for (const bad of ['', 'x'.repeat(10_000), 42, null, undefined, {}]) {
        expect(await a.consume(bad as string)).toBe(false);
      }
    });

    it('forgets a nonce after its retention, not before', async () => {
      const [a, b] = await backend().nonces({ retentionSeconds: 0.3 });
      const n = uniq('nonce');
      expect(await a.consume(n)).toBe(true);
      await sleep(100);
      expect(await b.consume(n)).toBe(false);
      await sleep(350);
      expect(await b.consume(n)).toBe(true);
      expect(await a.consume(n)).toBe(false);
    });

    it('keeps namespaces apart', async () => {
      const [inv] = await backend().nonces({ namespace: 'invocation' });
      const [other] = await backend().nonces({ namespace: 'other' });
      const n = uniq('nonce');
      expect(await inv.consume(n)).toBe(true);
      expect(await other.consume(n)).toBe(true);
    });

    it('makes each OpenID4VP response redeemable once across instances', async () => {
      const [sessionsA, sessionsB] = await backend().responseSessions();
      const [storeA, storeB] = await backend().requestSessions();
      const m = createMandate({ agentJwk: agent.publicJwk, actions: ['payments.*'], limits: { currency: 'EUR', total: 1000 } });

      // Instance A creates the request and stores the session; the wallet's POST lands on instance B.
      const req = await createMandateRequest({ mandate: m, clientId: CLIENT_ID, responseUri: 'https://agents.example/vp/r1' });
      const lookup = uniq('r');
      await storeA.put(lookup, req.session);
      const body = await wallet.respond(req.params);
      expect(body).toHaveProperty('response'); // encrypted: B needs the stored key

      const opts = (sessions: NonceStore) => ({ now: nowSeconds(), trustedIssuers: [provider.trusted], sessions });
      const sessionB = (await storeB.get(lookup))!;
      expect(sessionB.state).toBe(req.session.state);

      // The same response posted to both instances at once: exactly one succeeds.
      const sessionA = (await storeA.get(lookup))!;
      const settled = await Promise.allSettled([
        handleMandateResponse(body, sessionB, opts(sessionsB)),
        handleMandateResponse(body, sessionA, opts(sessionsA)),
      ]);
      expect(settled.filter((s) => s.status === 'fulfilled')).toHaveLength(1);
      const rejected = settled.find((s) => s.status === 'rejected') as PromiseRejectedResult;
      expect(String(rejected.reason?.message)).toMatch(/already been answered/);
      await expect(handleMandateResponse(body, sessionA, opts(sessionsA))).rejects.toThrow(/already been answered/);

      await storeB.delete(lookup);
      expect(await storeA.get(lookup)).toBeUndefined();
    });

    it('stores request sessions without overwriting a live one, and forgets them after their TTL', async () => {
      const [a, b] = await backend().requestSessions({ ttlSeconds: 0.3 });
      const m = createMandate({ agentJwk: agent.publicJwk, actions: ['payments.*'] });
      const req = await createMandateRequest({ mandate: m, clientId: CLIENT_ID, responseUri: 'https://agents.example/vp' });
      const other = await createMandateRequest({ mandate: m, clientId: CLIENT_ID, responseUri: 'https://agents.example/vp' });
      const id = uniq('s');
      await a.put(id, req.session);
      await expect(b.put(id, other.session)).rejects.toThrow(/already exists/);
      expect((await b.get(id))?.nonce).toBe(req.session.nonce);
      expect(await b.get(uniq('missing'))).toBeUndefined();
      await sleep(400);
      expect(await b.get(id)).toBeUndefined();
      await b.put(id, other.session); // an expired id can be reused
      expect((await a.get(id))?.nonce).toBe(other.session.nonce);
      await expect(a.put('', req.session)).rejects.toThrow();
    });
  });

  describe.skipIf(!enabled)(`${name}: revocation`, () => {
    it('shares revocations between instances', async () => {
      const [a, b] = await backend().revocations();
      const id = uniq('mandate');
      expect(await b.isRevoked(id)).toBe(false);
      await a.revoke(id, 'lost phone');
      await a.revoke(id);
      expect(await b.isRevoked(id)).toBe(true);
      await b.unrevoke(id);
      expect(await a.isRevoked(id)).toBe(false);
      await expect(a.isRevoked('x'.repeat(5000))).rejects.toThrow();
      await expect(a.revoke('')).rejects.toThrow();
    });

    it('denies a chain whose mandate was revoked on another instance', async () => {
      const [a, b] = await backend().revocations();
      const [ledger] = await backend().ledgers();
      const [nonces] = await backend().nonces();
      const { child, chain } = await delegatedChain(10_000, 5_000);
      await a.revoke(child.id);
      const d = await verifyAuthorization(chain, await pay(chain, child, 100), { audience: AUD, trustedIssuers: [provider.trusted], nonces, ledger, revocation: b });
      expect(d).toMatchObject({ decision: 'DENY', code: 'REVOKED', at: 1 });
    });
  });

  describe.skipIf(!enabled)(`${name}: end to end with verifyAuthorization`, () => {
    it('enforces totals and replay protection across two verifier replicas', async () => {
      const [ledgerA, ledgerB] = await backend().ledgers();
      const [noncesA, noncesB] = await backend().nonces();
      const replica = (ledger: SpendingLedger, nonces: NonceStore) => ({ audience: AUD, trustedIssuers: [provider.trusted], ledger, nonces });
      const A = replica(ledgerA, noncesA);
      const B = replica(ledgerB, noncesB);
      const { parent, child, chain } = await delegatedChain(30_000, 10_000);

      const first = await pay(chain, child, 4000);
      const d1 = await verifyAuthorization(chain, first, A);
      expect(d1.decision).toBe('ALLOW');
      if (d1.decision === 'ALLOW') await ledgerA.commit(d1.reservation!);

      // The same invocation replayed on the other replica: denied, and its reservation released.
      expect(await verifyAuthorization(chain, first, B)).toMatchObject({ decision: 'DENY', code: 'REPLAY' });
      expect(await ledgerB.spent(mandateHash(child), 'EUR')).toBe(4000);

      const d2 = await verifyAuthorization(chain, await pay(chain, child, 4000), B);
      expect(d2.decision).toBe('ALLOW');
      if (d2.decision === 'ALLOW') await ledgerB.commit(d2.reservation!);
      expect(await verifyAuthorization(chain, await pay(chain, child, 4000), A)).toMatchObject({ decision: 'DENY', code: 'LIMIT_TOTAL' });
      expect(await ledgerA.spent(mandateHash(child), 'EUR')).toBe(8000);
      expect(await ledgerA.spent(mandateHash(parent), 'EUR')).toBe(8000);
    });

    it('lets exactly as many parallel invocations through as the total allows', async () => {
      const [ledgerA, ledgerB] = await backend().ledgers();
      const [noncesA, noncesB] = await backend().nonces();
      const { child, chain } = await delegatedChain(30_000, 10_000);
      const invocations = await Promise.all(Array.from({ length: 12 }, () => pay(chain, child, 3000)));
      const decisions = await Promise.all(
        invocations.map((inv, i) =>
          verifyAuthorization(chain, inv, {
            audience: AUD,
            trustedIssuers: [provider.trusted],
            ledger: i % 2 ? ledgerA : ledgerB,
            nonces: i % 2 ? noncesA : noncesB,
          }),
        ),
      );
      const allowed = decisions.filter((d) => d.decision === 'ALLOW');
      expect(allowed).toHaveLength(3);
      expect(decisions.filter((d) => d.decision === 'DENY' && d.code === 'LIMIT_TOTAL')).toHaveLength(9);
      // Replaying all of them at once: none passes, and no amount stays reserved.
      const replays = await Promise.all(
        invocations.map((inv) => verifyAuthorization(chain, inv, { audience: AUD, trustedIssuers: [provider.trusted], ledger: ledgerA, nonces: noncesB })),
      );
      expect(replays.every((d) => d.decision === 'DENY')).toBe(true);
      expect(await ledgerB.spent(mandateHash(child), 'EUR')).toBe(9000);
    });
  });
}

// ---------------------------------------------------------------- Postgres

let pools: pg.Pool[] = [];

function pgBackend(): Backend {
  const [poolA, poolB] = pools;
  // Each call gets its own tables, so counts (sweeps) never see another test's rows.
  const fresh = async () => {
    const tablePrefix = `t${randomUUID().replace(/-/g, '').slice(0, 12)}_`;
    await migratePostgres(poolA, { tablePrefix });
    return tablePrefix;
  };
  return {
    async ledgers(opts = {}) {
      const tablePrefix = await fresh();
      return [new PostgresSpendingLedger(poolA, { tablePrefix, ...opts }), new PostgresSpendingLedger(poolB, { tablePrefix, ...opts })];
    },
    async nonces(opts = {}) {
      const tablePrefix = 'shared_';
      return [new PostgresNonceStore(poolA, { tablePrefix, ...opts }), new PostgresNonceStore(poolB, { tablePrefix, ...opts })];
    },
    async responseSessions() {
      return [createPostgresResponseSessionStore(poolA, { tablePrefix: 'shared_' }), createPostgresResponseSessionStore(poolB, { tablePrefix: 'shared_' })];
    },
    async requestSessions(opts = {}) {
      return [new PostgresMandateSessionStore(poolA, { tablePrefix: 'shared_', ...opts }), new PostgresMandateSessionStore(poolB, { tablePrefix: 'shared_', ...opts })];
    },
    async revocations() {
      return [new PostgresRevocationRegistry(poolA, { tablePrefix: 'shared_' }), new PostgresRevocationRegistry(poolB, { tablePrefix: 'shared_' })];
    },
  };
}

describe.skipIf(!pgEngine.ok)(`${pgLabel} setup`, () => {
  beforeAll(async () => {
    if (!pgEngine.ok) return;
    pools = [new pg.Pool({ connectionString: pgEngine.url, max: 12 }), new pg.Pool({ connectionString: pgEngine.url, max: 12 })];
    // Every replica migrates at start-up; the advisory lock serialises them.
    await Promise.all([...pools, ...pools].map((p) => migratePostgres(p, { tablePrefix: 'shared_' })));
  });

  it('accepts a pg Pool and Client as SqlClient', () => {
    const asClient: SqlClient = pools[0];
    const asPgClient: SqlClient = new pg.Client();
    expect(asClient && asPgClient).toBeTruthy();
  });

  it('ships a schema.sql identical to postgresSchema(), which applies on an empty database', async () => {
    const file = readFileSync(new URL('../src/stores/schema.sql', import.meta.url), 'utf8');
    expect(file).toBe(POSTGRES_SCHEMA_SQL);
    expect(postgresSchema({ tablePrefix: 'x_', schema: 'bank' })).toContain('bank.x_ledger');
    const dbName = `sqlfile_${randomUUID().replace(/-/g, '').slice(0, 8)}`;
    await pools[0].query(`CREATE DATABASE ${dbName}`);
    const url = new URL(pgEngine.ok ? pgEngine.url : '');
    url.pathname = `/${dbName}`;
    const c = new pg.Client({ connectionString: url.toString() });
    await c.connect();
    try {
      await c.query(file); // simple query protocol: the whole file, as psql -f would run it
      await c.query(file); // and again: idempotent
      const ledger = new PostgresSpendingLedger(c);
      const id = await ledger.reserve([{ key: 'k', total: 10 }], EUR(10));
      expect(id).not.toBeNull();
      expect(await ledger.reserve([{ key: 'k', total: 10 }], EUR(1))).toBeNull();
    } finally {
      await c.end();
    }
  });

  it('upgrades a version 1 schema in place, keeping its rows and the meaning of legacy expired ones', async () => {
    const dbName = `upgrade_${randomUUID().replace(/-/g, '').slice(0, 8)}`;
    await pools[0].query(`CREATE DATABASE ${dbName}`);
    const url = new URL(pgEngine.ok ? pgEngine.url : '');
    url.pathname = `/${dbName}`;
    const c = new pg.Client({ connectionString: url.toString() });
    await c.connect();
    try {
      await c.query(readFileSync(new URL('./stores-schema-v1.sql', import.meta.url), 'utf8'));
      // A version 1 sweep gave the amount back and left the state 'expired'.
      const legacy = randomUUID();
      await c.query(`SELECT plenipo_ledger_reserve($1::uuid, ARRAY['k'], ARRAY[1000]::bigint[], 'EUR', 70, 0.001)`, [legacy]);
      await sleep(20);
      await c.query('SELECT plenipo_ledger_expire(10)');
      expect((await c.query('SELECT state FROM plenipo_reservations WHERE id = $1', [legacy])).rows).toEqual([{ state: 'expired' }]);
      expect(await new PostgresSpendingLedger(c).spent('k', 'EUR')).toBe(0);

      await Promise.all([migratePostgres(c), migratePostgres(c)]);
      expect((await c.query('SELECT version FROM plenipo_schema_meta')).rows).toEqual([{ version: 3 }]);
      const ledger = new PostgresSpendingLedger(c, { pendingTtlSeconds: 0.05 });
      // The legacy row is under-counted (its outcome is unknown): it is on the reconciliation list and
      // survives purges until reconciled.
      expect((await ledger.unresolved()).map((r) => r.id)).toEqual([legacy]);
      await sleep(20);
      expect(await ledger.purgeSettled({ olderThanSeconds: 0.001 })).toBe(0);
      // A late commit counts it again.
      expect(await ledger.commit(legacy)).toBeUndefined();
      expect(await ledger.unresolved()).toEqual([]);
      expect(await ledger.spent('k', 'EUR')).toBe(70);
      // New sweeps count as spent.
      const stale = await ledger.reserve([{ key: 'k', total: 1000 }], EUR(30));
      await sleep(100);
      expect(await ledger.sweepExpired()).toBe(1);
      expect((await ledger.reservation(stale!))?.state).toBe('expired_spent');
      expect(await ledger.spent('k', 'EUR')).toBe(100);
    } finally {
      await c.end();
    }
  });

  it('upgrades a version 2 schema in place: released rows can then be corrected', async () => {
    const dbName = `upgrade2_${randomUUID().replace(/-/g, '').slice(0, 8)}`;
    await pools[0].query(`CREATE DATABASE ${dbName}`);
    const url = new URL(pgEngine.ok ? pgEngine.url : '');
    url.pathname = `/${dbName}`;
    const c = new pg.Client({ connectionString: url.toString() });
    await c.connect();
    try {
      await c.query(readFileSync(new URL('./stores-schema-v2.sql', import.meta.url), 'utf8'));
      const id = randomUUID();
      await c.query(`SELECT plenipo_ledger_reserve($1::uuid, ARRAY['k'], ARRAY[100]::bigint[], 'EUR', 60, 900)`, [id]);
      await c.query(`SELECT plenipo_ledger_settle($1::uuid, 'release')`, [id]);
      // Version 2 ignored a commit after a release.
      expect((await c.query(`SELECT plenipo_ledger_settle($1::uuid, 'commit') AS s`, [id])).rows).toEqual([{ s: 'released' }]);

      await Promise.all([migratePostgres(c), migratePostgres(c)]);
      expect((await c.query('SELECT version FROM plenipo_schema_meta')).rows).toEqual([{ version: 3 }]);
      const ledger = new PostgresSpendingLedger(c);
      expect(await ledger.reconcile(id, 'executed')).toBe('committed');
      expect(await ledger.spent('k', 'EUR')).toBe(60);
      const info = await ledger.reservation(id);
      expect(info?.correctedAt).toBeInstanceOf(Date);
      expect(info?.releasedBy).toBeUndefined(); // released before version 3 recorded who released
    } finally {
      await c.end();
    }
  });

  it('refuses table prefixes and schemas that are not plain identifiers', () => {
    for (const tablePrefix of ['x; DROP TABLE y; --', 'X_', '1x', 'a'.repeat(31), 'a-b']) {
      expect(() => new PostgresSpendingLedger(pools[0], { tablePrefix })).toThrow(/tablePrefix/);
    }
    expect(() => new PostgresNonceStore(pools[0], { schema: 'public"' })).toThrow(/schema/);
    expect(() => new PostgresNonceStore(pools[0], { namespace: 'a b' })).toThrow(/namespace/);
    expect(() => new PostgresSpendingLedger(pools[0], { pendingTtlSeconds: 0 })).toThrow();
    expect(() => new PostgresNonceStore(pools[0], { retentionSeconds: 10 ** 9 })).toThrow();
  });

  it('works inside a schema of its own', async () => {
    await pools[0].query('CREATE SCHEMA IF NOT EXISTS bank');
    await migratePostgres(pools[0], { schema: 'bank', tablePrefix: 'p_' });
    const l = new PostgresSpendingLedger(pools[1], { schema: 'bank', tablePrefix: 'p_' });
    const id = await l.reserve([{ key: 'k', total: 5 }], EUR(5));
    await l.commit(id!);
    const { rows } = await pools[0].query('SELECT committed FROM bank.p_ledger');
    expect(rows).toEqual([{ committed: '5' }]);
  });

  it('keeps revocations, spending and nonces across a server restart', async () => {
    if (!pgEngine.ok || !pgEngine.restart) return;
    const tablePrefix = 'restart_';
    await migratePostgres(pools[0], { tablePrefix });
    await new PostgresRevocationRegistry(pools[0], { tablePrefix }).revoke('mandate-restart', 'test');
    const r = await new PostgresSpendingLedger(pools[0], { tablePrefix }).reserve([{ key: 'k', total: 100 }], EUR(60));
    await new PostgresSpendingLedger(pools[0], { tablePrefix }).commit(r!);
    expect(await new PostgresNonceStore(pools[0], { tablePrefix }).consume('n-restart')).toBe(true);

    await Promise.all(pools.map((p) => p.end()));
    await pgEngine.restart();
    pools = [new pg.Pool({ connectionString: pgEngine.url, max: 12 }), new pg.Pool({ connectionString: pgEngine.url, max: 12 })];

    expect(await new PostgresRevocationRegistry(pools[1], { tablePrefix }).isRevoked('mandate-restart')).toBe(true);
    expect(await new PostgresSpendingLedger(pools[1], { tablePrefix }).spent('k', 'EUR')).toBe(60);
    expect(await new PostgresSpendingLedger(pools[1], { tablePrefix }).reserve([{ key: 'k', total: 100 }], EUR(41))).toBeNull();
    expect(await new PostgresNonceStore(pools[1], { tablePrefix }).consume('n-restart')).toBe(false);
  });

  it('sweeps expired nonces and request sessions, and purges old settled reservations', async () => {
    const tablePrefix = `sw${randomUUID().replace(/-/g, '').slice(0, 8)}_`;
    await migratePostgres(pools[0], { tablePrefix });
    const nonces = new PostgresNonceStore(pools[0], { tablePrefix, retentionSeconds: 0.2 });
    const sessions = new PostgresMandateSessionStore(pools[1], { tablePrefix, ttlSeconds: 0.2 });
    const ledger = new PostgresSpendingLedger(pools[0], { tablePrefix });
    await nonces.consume('a');
    await nonces.consume('b');
    const m = createMandate({ agentJwk: agent.publicJwk, actions: ['x'] });
    await sessions.put('s1', (await createMandateRequest({ mandate: m, clientId: CLIENT_ID, responseUri: 'https://a.example/vp' })).session);
    const settledId = await ledger.reserve([{ key: 'k' }], EUR(1));
    await ledger.release(settledId!);
    const pendingId = await ledger.reserve([{ key: 'k' }], EUR(1));
    await sleep(300);
    expect(await nonces.sweep()).toBe(2);
    expect(await sessions.sweep()).toBe(1);
    expect(await ledger.purgeSettled({ olderThanSeconds: 0.1 })).toBe(1);
    expect(await ledger.reservation(settledId!)).toBeUndefined();
    expect((await ledger.reservation(pendingId!))?.state).toBe('pending');
  });

  afterAll(async () => {
    await Promise.all(pools.map((p) => p.end()));
  });

  contract(pgLabel, pgEngine.ok, pgBackend);
});

// ---------------------------------------------------------------- Redis

let io: Redis | undefined;
let nodeRedis: ReturnType<typeof createClient> | undefined;

function redisBackend(): Backend {
  const a = fromIoredis(io!);
  const b = fromNodeRedis(nodeRedis!);
  const prefix = `t-${randomUUID()}`;
  return {
    async ledgers(opts = {}) {
      return [new RedisSpendingLedger(a, { prefix, ...opts }), new RedisSpendingLedger(b, { prefix, ...opts })];
    },
    async nonces(opts = {}) {
      return [new RedisNonceStore(a, { prefix: 'shared', ...opts }), new RedisNonceStore(b, { prefix: 'shared', ...opts })];
    },
    async responseSessions() {
      return [createRedisResponseSessionStore(a), createRedisResponseSessionStore(b)];
    },
    async requestSessions(opts = {}) {
      return [new RedisMandateSessionStore(a, { prefix, ...opts }), new RedisMandateSessionStore(b, { prefix, ...opts })];
    },
    async revocations() {
      return [new RedisRevocationRegistry(a, { prefix }), new RedisRevocationRegistry(b, { prefix })];
    },
  };
}

describe.skipIf(!redisEngine.ok)(`${redisLabel} setup`, () => {
  beforeAll(async () => {
    if (!redisEngine.ok) return;
    io = new Redis(redisEngine.url, { lazyConnect: true, maxRetriesPerRequest: 1 });
    await io.connect();
    nodeRedis = createClient({ url: redisEngine.url });
    await nodeRedis.connect();
  });

  afterAll(async () => {
    io?.disconnect();
    await nodeRedis?.quit();
  });

  it('puts every key of a ledger under one hash tag, so it stays in one cluster slot', async () => {
    const prefix = `tag-${randomUUID()}`;
    const l = new RedisSpendingLedger(fromIoredis(io!), { prefix });
    const id = await l.reserve([{ key: 'a', total: 10 }, { key: 'b' }], EUR(5));
    await l.commit(id!);
    await l.reserve([{ key: 'a', total: 10 }], EUR(1));
    const keys = await io!.keys(`*${prefix}*`);
    expect(keys.length).toBeGreaterThanOrEqual(4);
    for (const k of keys) expect(k.startsWith(`{${prefix}:ledger}:`)).toBe(true);
    expect(() => new RedisSpendingLedger(fromIoredis(io!), { prefix: 'a{b}' })).toThrow(/prefix/);
  });

  it('reloads its scripts after SCRIPT FLUSH (restart or failover)', async () => {
    const l = new RedisSpendingLedger(fromNodeRedis(nodeRedis!), { prefix: `flush-${randomUUID()}` });
    await io!.script('FLUSH');
    const id = await l.reserve([{ key: 'k', total: 10 }], EUR(10));
    expect(id).not.toBeNull();
    await io!.script('FLUSH');
    await l.release(id!);
    expect(await l.spent('k', 'EUR')).toBe(0);
  });

  it('hashes nonces and session ids into keys of bounded size', async () => {
    const s = new RedisNonceStore(fromIoredis(io!), { prefix: 'hash-test' });
    expect(await s.consume('{tag}' + 'x'.repeat(200))).toBe(true);
    const keys = await io!.keys('hash-test:*');
    expect(keys).toHaveLength(1);
    expect(keys[0]).not.toContain('{');
    expect(keys[0].length).toBeLessThan(100);
  });

  contract(redisLabel, redisEngine.ok, redisBackend);
});

// ---------------------------------------------------------------- PGlite: driver compatibility

describe('PGlite as SqlClient', () => {
  it('runs the migration and every Postgres store in-process', async () => {
    const db = new PGlite();
    try {
      const client: SqlClient = db;
      await migratePostgres(client);
      const ledger = new PostgresSpendingLedger(client, { pendingTtlSeconds: 0.2 });
      const id = await ledger.reserve([{ key: 'b', total: 100 }, { key: 'a' }], EUR(60));
      expect(await ledger.reserve([{ key: 'b', total: 100 }], EUR(41))).toBeNull();
      await ledger.commit(id!);
      expect(await ledger.spent('a', 'EUR')).toBe(60);
      const stale = await ledger.reserve([{ key: 'b', total: 100 }], EUR(40));
      await sleep(300);
      expect(await ledger.sweepExpired()).toBe(1);
      expect((await ledger.reservation(stale!))?.state).toBe('expired_spent');
      expect(await ledger.spent('b', 'EUR')).toBe(100);
      expect(await ledger.reconcile(stale!, 'not_executed')).toBe('released');
      expect(await ledger.spent('b', 'EUR')).toBe(60);

      const nonces = new PostgresNonceStore(client);
      expect(await nonces.consume('n')).toBe(true);
      expect(await nonces.consume('n')).toBe(false);
      const rev = new PostgresRevocationRegistry(client);
      await rev.revoke('m-1');
      expect(await rev.isRevoked('m-1')).toBe(true);
      const sessions = new PostgresMandateSessionStore(client);
      const m = createMandate({ agentJwk: agent.publicJwk, actions: ['x'] });
      const req = await createMandateRequest({ mandate: m, clientId: CLIENT_ID, responseUri: 'https://a.example/vp' });
      await sessions.put('r', req.session);
      expect((await sessions.get('r'))?.state).toBe(req.session.state);
    } finally {
      await db.close();
    }
  }, 60_000);
});

describe('store helpers', () => {
  it('derives a nonce retention that covers the verifier acceptance window', () => {
    expect(nonceRetentionSeconds()).toBe(240);
    expect(nonceRetentionSeconds({ maxInvocationAgeSeconds: 30, skewSeconds: 5, marginSeconds: 0 })).toBe(35);
  });
});

afterAll(async () => {
  if (pgEngine.ok) await pgEngine.stop();
  if (redisEngine.ok) await redisEngine.stop();
}, 30_000);
