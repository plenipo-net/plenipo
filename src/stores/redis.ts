/**
 * Redis implementations of the stateful interfaces. Multi-key updates run as Lua scripts, which Redis
 * executes atomically: no other command runs between the check and the increment.
 *
 * No driver is imported: the stores take a {@link RedisClient}; `fromIoredis` and `fromNodeRedis`
 * adapt the two common clients. On Redis Cluster every key of one ledger carries the same hash tag,
 * so the ledger lives in one slot (one shard) and its scripts stay atomic.
 *
 * Durability is Redis's: without AOF persistence and with asynchronous replication, a restart or a
 * failover can forget reservations, nonces and revocations. See docs/stores.md before using Redis
 * for spending limits or revocation.
 */
import { createHash, randomUUID } from 'node:crypto';
import { sha256 } from '../encoding.js';
import type { MandateRequestSession } from '../openid4vp.js';
import type { LedgerEntry, NonceStore, SpendingLedger } from '../registry.js';
import type { Amount } from '../types.js';
import {
  deserializeSession,
  durationSeconds,
  isReservationId,
  nonceDigest,
  normalizeEntries,
  positiveInt,
  serializeSession,
  toSafeInteger,
  validateAmount,
  validateCurrency,
  validateKey,
  validateMandateId,
  validateSessionId,
  type ManagedRevocationRegistry,
  type MandateSessionStore,
  type ReconcileOutcome,
  type ReservationInfo,
  type ReservationState,
} from './common.js';

/** The commands the stores need, in a driver-neutral shape. Arguments are always strings. */
export interface RedisClient {
  eval(script: string, keys: string[], args: string[]): Promise<unknown>;
  /** Must reject with an error whose message contains NOSCRIPT when the script is not cached. */
  evalsha(sha1: string, keys: string[], args: string[]): Promise<unknown>;
  /** SET key value PX ms NX: resolves 'OK' when the key was set, null when it already existed. */
  setNxPx(key: string, value: string, ttlMs: number): Promise<unknown>;
}

/** The subset of an ioredis client (Redis or Cluster) that {@link fromIoredis} uses. */
export interface IoredisLike {
  eval(script: string, numkeys: number, ...keysAndArgs: string[]): Promise<unknown>;
  evalsha(sha1: string, numkeys: number, ...keysAndArgs: string[]): Promise<unknown>;
  set(key: string, value: string, px: 'PX', ms: number, nx: 'NX'): Promise<unknown>;
}

/** Adapts an ioredis `Redis` or `Cluster` instance. */
export function fromIoredis(client: IoredisLike): RedisClient {
  return {
    eval: (script, keys, args) => client.eval(script, keys.length, ...keys, ...args),
    evalsha: (sha, keys, args) => client.evalsha(sha, keys.length, ...keys, ...args),
    setNxPx: (key, value, ms) => client.set(key, value, 'PX', ms, 'NX'),
  };
}

/** The subset of a node-redis (v4 and later) client that {@link fromNodeRedis} uses. */
export interface NodeRedisLike {
  eval(script: string, options: { keys: string[]; arguments: string[] }): Promise<unknown>;
  evalSha(sha1: string, options: { keys: string[]; arguments: string[] }): Promise<unknown>;
  set(key: string, value: string, options: { PX: number; NX: true }): Promise<unknown>;
}

/** Adapts a node-redis client (`createClient()` or `createCluster()`), v4 or later. */
export function fromNodeRedis(client: NodeRedisLike): RedisClient {
  return {
    eval: (script, keys, args) => client.eval(script, { keys, arguments: args }),
    evalsha: (sha, keys, args) => client.evalSha(sha, { keys, arguments: args }),
    setNxPx: (key, value, ms) => client.set(key, value, { PX: ms, NX: true }),
  };
}

class Script {
  readonly sha: string;
  constructor(readonly source: string) {
    this.sha = createHash('sha1').update(source).digest('hex');
  }
  /** EVALSHA first; on a node that has not cached the script yet (restart, failover, cluster), EVAL. */
  async run(redis: RedisClient, keys: string[], args: string[]): Promise<unknown> {
    try {
      return await redis.evalsha(this.sha, keys, args);
    } catch (e) {
      if (!String((e as Error)?.message ?? e).includes('NOSCRIPT')) throw e;
      return redis.eval(this.source, keys, args);
    }
  }
}

/** Server time in milliseconds: one clock for every instance. Allowed before writes since Redis 5 (effects replication). */
const NOW = `
if redis.replicate_commands then redis.replicate_commands() end
local t = redis.call('TIME')
local now = tonumber(t[1]) * 1000 + math.floor(tonumber(t[2]) / 1000)
`;

// KEYS: committed, pending, reservation, expiry index. ARGV: currency, amount, ttl ms, id, n, then key/total pairs.
const RESERVE = new Script(`${NOW}
local currency = ARGV[1]
local amount = tonumber(ARGV[2])
local n = tonumber(ARGV[5])
if redis.call('EXISTS', KEYS[3]) == 1 then return redis.error_reply('plenipo: reservation id collision') end
local fields = {}
for i = 1, n do
  local f = currency .. ':' .. ARGV[4 + 2 * i]
  fields[i] = f
  local total = ARGV[5 + 2 * i]
  if total ~= '' then
    local c = tonumber(redis.call('HGET', KEYS[1], f) or '0')
    local p = tonumber(redis.call('HGET', KEYS[2], f) or '0')
    if c + p + amount > tonumber(total) then return 0 end
  end
end
for i = 1, n do redis.call('HINCRBY', KEYS[2], fields[i], amount) end
local expires = now + tonumber(ARGV[3])
redis.call('HSET', KEYS[3], 'state', 'pending', 'currency', currency, 'amount', ARGV[2],
  'keys', cjson.encode(fields), 'created', now, 'expires', expires)
redis.call('ZADD', KEYS[4], expires, ARGV[4])
return 1
`);

// Shared tail of settle and expire: adds the deltas to every ledger field of the reservation and
// records the new state. `keep` leaves the reservation without TTL (expired_spent waits for reconciliation).
const APPLY = `
local function apply(d_pending, d_committed, to_state, retention, id, keep)
  local amount = tonumber(redis.call('HGET', KEYS[3], 'amount'))
  local fields = cjson.decode(redis.call('HGET', KEYS[3], 'keys'))
  -- A zero amount is skipped: Lua would format -0 as "-0", which HINCRBY rejects.
  if amount > 0 then
    for _, f in ipairs(fields) do
      if d_pending ~= 0 then
        if redis.call('HINCRBY', KEYS[2], f, d_pending * amount) == 0 then redis.call('HDEL', KEYS[2], f) end
      end
      if d_committed ~= 0 then redis.call('HINCRBY', KEYS[1], f, d_committed * amount) end
    end
  end
  redis.call('HSET', KEYS[3], 'state', to_state, 'settled', now)
  redis.call('ZREM', KEYS[4], id)
  if keep then
    redis.call('ZADD', KEYS[5], now, id)
  else
    redis.call('ZREM', KEYS[5], id)
    redis.call('PEXPIRE', KEYS[3], retention)
  end
  return to_state
end
`;

// KEYS: committed, pending, reservation, expiry index, unresolved index. ARGV: action, retention ms, id.
// Transitions as in the Postgres ledger_settle function; evidence that the action ran always wins:
//   commit        pending -> committed; expired_spent -> committed (already counted);
//                 released or expired (v1) -> committed, the amount counted again (released: corrected)
//   release       pending -> released (never expired_spent: its outcome is unknown)
//   not_executed  pending or expired_spent -> released, amount given back; expired (v1) -> released
// A release records who released (released_by), a correction when it happened (corrected).
const SETTLE = new Script(`${NOW}${APPLY}
local state = redis.call('HGET', KEYS[3], 'state')
if not state then return 'unknown' end
local action = ARGV[1]
local function released(dp, dc)
  apply(dp, dc, 'released', ARGV[2], ARGV[3], false)
  redis.call('HSET', KEYS[3], 'released_by', action == 'release' and 'release' or 'reconcile')
  return 'released'
end
if action == 'commit' then
  if state == 'pending' then return apply(-1, 1, 'committed', ARGV[2], ARGV[3], false) end
  if state == 'expired_spent' then return apply(0, 0, 'committed', ARGV[2], ARGV[3], false) end
  if state == 'expired' then return apply(0, 1, 'committed', ARGV[2], ARGV[3], false) end
  if state == 'released' then
    apply(0, 1, 'committed', ARGV[2], ARGV[3], false)
    redis.call('HSET', KEYS[3], 'corrected', now)
    return 'committed'
  end
elseif action == 'release' or action == 'not_executed' then
  if state == 'pending' then return released(-1, 0) end
  if action == 'not_executed' and state == 'expired_spent' then return released(0, -1) end
  if action == 'not_executed' and state == 'expired' then return released(0, 0) end
else
  return redis.error_reply('plenipo: invalid action')
end
return state
`);

// KEYS: unresolved index. ARGV: scan cursor, count, key pattern, reservation key prefix.
// One step of adopting version 1 'expired' reservations: they lose their TTL and join the
// reconciliation work list. The reservation keys share the index's hash tag, so they live in its slot.
const ADOPT_LEGACY = new Script(`
local r = redis.call('SCAN', ARGV[1], 'MATCH', ARGV[3], 'COUNT', tonumber(ARGV[2]))
local n = 0
for _, k in ipairs(r[2]) do
  if redis.call('HGET', k, 'state') == 'expired' then
    redis.call('PERSIST', k)
    redis.call('ZADD', KEYS[1], tonumber(redis.call('HGET', k, 'settled') or '0'), string.sub(k, string.len(ARGV[4]) + 1))
    n = n + 1
  end
end
return { r[1], n }
`);

// KEYS: committed, pending, reservation, expiry index, unresolved index. ARGV: retention ms, id.
// A stale pending reservation becomes expired_spent: its amount moves from pending to committed.
const EXPIRE_ONE = new Script(`${NOW}${APPLY}
local state = redis.call('HGET', KEYS[3], 'state')
if state ~= 'pending' then
  redis.call('ZREM', KEYS[4], ARGV[2])
  return 0
end
if tonumber(redis.call('HGET', KEYS[3], 'expires')) > now then return 0 end
apply(-1, 1, 'expired_spent', ARGV[1], ARGV[2], true)
return 1
`);

// KEYS: unresolved index. ARGV: limit.
const LIST_UNRESOLVED = new Script(`return redis.call('ZRANGE', KEYS[1], 0, tonumber(ARGV[1]) - 1)`);

// KEYS: expiry index. ARGV: limit.
const LIST_EXPIRED = new Script(`${NOW}
return redis.call('ZRANGEBYSCORE', KEYS[1], '-inf', now, 'LIMIT', 0, tonumber(ARGV[1]))
`);

// KEYS: committed, pending. ARGV: field.
const SPENT = new Script(`
local c = tonumber(redis.call('HGET', KEYS[1], ARGV[1]) or '0')
local p = tonumber(redis.call('HGET', KEYS[2], ARGV[1]) or '0')
return c + p
`);

const HGETALL = new Script(`return redis.call('HGETALL', KEYS[1])`);
const GET = new Script(`return redis.call('GET', KEYS[1])`);
const DEL = new Script(`return redis.call('DEL', KEYS[1])`);
const HSETNX = new Script(`return redis.call('HSETNX', KEYS[1], ARGV[1], ARGV[2])`);
const HDEL = new Script(`return redis.call('HDEL', KEYS[1], ARGV[1])`);
const HEXISTS = new Script(`return redis.call('HEXISTS', KEYS[1], ARGV[1])`);

const PREFIX_RE = /^[A-Za-z0-9_.:-]{1,64}$/;

/** Key prefixes cannot contain braces: a stray hash tag would split a ledger across slots. */
function checkPrefix(prefix: string | undefined): string {
  const p = prefix ?? 'plenipo';
  if (typeof p !== 'string' || !PREFIX_RE.test(p)) throw new RangeError('prefix must match /^[A-Za-z0-9_.:-]{1,64}$/');
  return p;
}

export interface RedisLedgerOptions {
  /** Key prefix. Default `plenipo`. Keys are `{<prefix>:ledger}:…`, one hash slot per ledger. */
  prefix?: string;
  /** How long a reservation may stay pending before `sweepExpired` releases it. Default 900. */
  pendingTtlSeconds?: number;
  /**
   * How long a committed or released reservation is kept, so that a repeated commit or release stays a
   * no-op. Default 7 days. `expired_spent` reservations are kept until reconciled.
   */
  settledRetentionSeconds?: number;
}

export class RedisSpendingLedger implements SpendingLedger {
  private readonly tag: string;
  private readonly ttlMs: number;
  private readonly retentionMs: number;

  constructor(
    private readonly redis: RedisClient,
    opts: RedisLedgerOptions = {},
  ) {
    this.tag = `{${checkPrefix(opts.prefix)}:ledger}`;
    this.ttlMs = Math.max(1, Math.round(durationSeconds('pendingTtlSeconds', opts.pendingTtlSeconds, 900) * 1000));
    this.retentionMs = Math.max(1, Math.round(durationSeconds('settledRetentionSeconds', opts.settledRetentionSeconds, 7 * 24 * 3600) * 1000));
  }

  private keys(id: string): string[] {
    return [`${this.tag}:committed`, `${this.tag}:pending`, `${this.tag}:res:${id}`, `${this.tag}:expiry`, `${this.tag}:unresolved`];
  }

  async spent(key: string, currency: string): Promise<number> {
    validateKey(key);
    validateCurrency(currency);
    const r = await SPENT.run(this.redis, [`${this.tag}:committed`, `${this.tag}:pending`], [`${currency}:${key}`]);
    return toSafeInteger(r, 'spent');
  }

  async reserve(entries: LedgerEntry[], amount: Amount): Promise<string | null> {
    validateAmount(amount);
    const { keys, totals } = normalizeEntries(entries);
    const id = randomUUID();
    const args = [amount.currency, String(amount.value), String(this.ttlMs), id, String(keys.length)];
    keys.forEach((k, i) => args.push(k, totals[i] === null ? '' : String(totals[i])));
    const r = await RESERVE.run(this.redis, this.keys(id), args);
    return Number(r) === 1 ? id : null;
  }

  async commit(reservationId: string): Promise<void> {
    await this.settle(reservationId, 'commit');
  }

  async release(reservationId: string): Promise<void> {
    await this.settle(reservationId, 'release');
  }

  /** See `PostgresSpendingLedger.settle`: a release never gives back an `expired_spent` reservation. */
  async settle(reservationId: string, action: 'commit' | 'release'): Promise<ReservationState | 'unknown'> {
    if (action !== 'commit' && action !== 'release') throw new RangeError('action must be commit or release');
    return this.apply(reservationId, action);
  }

  /** See `PostgresSpendingLedger.reconcile`. */
  async reconcile(reservationId: string, outcome: ReconcileOutcome): Promise<ReservationState | 'unknown'> {
    if (outcome !== 'executed' && outcome !== 'not_executed') throw new RangeError('outcome must be executed or not_executed');
    return this.apply(reservationId, outcome === 'executed' ? 'commit' : 'not_executed');
  }

  private async apply(reservationId: string, action: 'commit' | 'release' | 'not_executed'): Promise<ReservationState | 'unknown'> {
    if (!isReservationId(reservationId)) return 'unknown';
    const r = await SETTLE.run(this.redis, this.keys(reservationId), [action, String(this.retentionMs), reservationId]);
    return String(r) as ReservationState | 'unknown';
  }

  /** Counts stale pending reservations as spent (`expired_spent`); see `PostgresSpendingLedger.sweepExpired`. */
  async sweepExpired(opts: { limit?: number } = {}): Promise<number> {
    const limit = positiveInt('limit', opts.limit, 1000);
    const ids = await LIST_EXPIRED.run(this.redis, [`${this.tag}:expiry`], [String(limit)]);
    if (!Array.isArray(ids)) return 0;
    let n = 0;
    for (const id of ids) {
      const s = String(id);
      if (!isReservationId(s)) continue;
      n += Number(await EXPIRE_ONE.run(this.redis, this.keys(s), [String(this.retentionMs), s]));
    }
    return n;
  }

  /** Reservations counted as spent by the sweep and not reconciled yet, oldest first. */
  async unresolved(opts: { limit?: number } = {}): Promise<ReservationInfo[]> {
    const limit = positiveInt('limit', opts.limit, 1000);
    const ids = await LIST_UNRESOLVED.run(this.redis, [`${this.tag}:unresolved`], [String(limit)]);
    if (!Array.isArray(ids)) return [];
    const out: ReservationInfo[] = [];
    for (const id of ids) {
      const info = await this.reservation(String(id));
      if (info?.state === 'expired_spent' || info?.state === 'expired') out.push(info);
    }
    return out;
  }

  /**
   * One-off upgrade for ledgers written before reconciliation existed: puts their legacy `expired`
   * reservations (amount given back by the old sweep, outcome unknown) on the {@link unresolved} list and
   * removes their TTL. Scans the ledger's keys; run it once after upgrading. Returns how many it adopted.
   */
  async adoptLegacyExpired(opts: { count?: number } = {}): Promise<number> {
    const count = positiveInt('count', opts.count, 1000);
    const resPrefix = `${this.tag}:res:`;
    // SCAN patterns treat braces literally except for glob characters, which the prefix cannot contain.
    const pattern = `${resPrefix.replace(/[[\]*?\\]/g, '\\$&')}*`;
    let cursor = '0';
    let adopted = 0;
    do {
      const r = await ADOPT_LEGACY.run(this.redis, [`${this.tag}:unresolved`], [cursor, String(count), pattern, resPrefix]);
      if (!Array.isArray(r) || r.length !== 2) throw new TypeError('unexpected reply from Redis');
      cursor = String(r[0]);
      adopted += Number(r[1]);
    } while (cursor !== '0');
    return adopted;
  }

  async reservation(reservationId: string): Promise<ReservationInfo | undefined> {
    if (!isReservationId(reservationId)) return undefined;
    const flat = await HGETALL.run(this.redis, [`${this.tag}:res:${reservationId}`], []);
    if (!Array.isArray(flat) || flat.length === 0) return undefined;
    const h: Record<string, string> = {};
    for (let i = 0; i + 1 < flat.length; i += 2) h[String(flat[i])] = String(flat[i + 1]);
    const prefix = `${h.currency}:`;
    return {
      id: reservationId,
      state: h.state as ReservationState,
      keys: (JSON.parse(h.keys) as string[]).map((f) => f.slice(prefix.length)),
      currency: h.currency,
      amount: toSafeInteger(h.amount, 'amount'),
      createdAt: new Date(toSafeInteger(h.created, 'created')),
      expiresAt: new Date(toSafeInteger(h.expires, 'expires')),
      ...(h.settled ? { settledAt: new Date(toSafeInteger(h.settled, 'settled')) } : {}),
      ...(h.released_by === 'release' || h.released_by === 'reconcile' ? { releasedBy: h.released_by } : {}),
      ...(h.corrected ? { correctedAt: new Date(toSafeInteger(h.corrected, 'corrected')) } : {}),
    };
  }
}

export interface RedisNonceOptions {
  prefix?: string;
  /** Separates invocation nonces from OpenID4VP sessions. Default `invocation`. */
  namespace?: string;
  /** How long a consumed nonce is remembered; see `PostgresNonceOptions.retentionSeconds`. Default 600. */
  retentionSeconds?: number;
}

/** Single-use nonces with SET NX PX: the first SET wins, and the key expires after the retention. */
export class RedisNonceStore implements NonceStore {
  private readonly base: string;
  private readonly retentionMs: number;
  /** How long a consumed nonce is remembered, so a verifier can check it covers its acceptance window. */
  readonly retentionSeconds: number;

  constructor(
    private readonly redis: RedisClient,
    opts: RedisNonceOptions = {},
  ) {
    const ns = opts.namespace ?? 'invocation';
    if (typeof ns !== 'string' || !PREFIX_RE.test(ns)) throw new RangeError('namespace must match /^[A-Za-z0-9_.:-]{1,64}$/');
    this.base = `${checkPrefix(opts.prefix)}:nonce:${ns}:`;
    this.retentionSeconds = durationSeconds('retentionSeconds', opts.retentionSeconds, 600);
    this.retentionMs = Math.max(1, Math.round(this.retentionSeconds * 1000));
  }

  async consume(nonce: string): Promise<boolean> {
    const digest = nonceDigest(nonce);
    if (!digest) return false;
    const r = await this.redis.setNxPx(this.base + digest, '1', this.retentionMs);
    return r === 'OK';
  }
}

/** The `sessions` store for `handleMandateResponse`, in its own namespace; see `createPostgresResponseSessionStore`. */
export function createRedisResponseSessionStore(
  redis: RedisClient,
  opts: { prefix?: string; maxAgeSeconds?: number; namespace?: string } = {},
): RedisNonceStore {
  return new RedisNonceStore(redis, {
    prefix: opts.prefix,
    namespace: opts.namespace ?? 'openid4vp-response',
    retentionSeconds: (opts.maxAgeSeconds ?? 600) + 60,
  });
}

/** Revocations in one Redis hash: mandate id to revocation time and reason. */
export class RedisRevocationRegistry implements ManagedRevocationRegistry {
  private readonly key: string;
  constructor(
    private readonly redis: RedisClient,
    opts: { prefix?: string } = {},
  ) {
    this.key = `${checkPrefix(opts.prefix)}:revocations`;
  }

  async revoke(mandateId: string, reason?: string): Promise<void> {
    validateMandateId(mandateId);
    if (reason !== undefined && (typeof reason !== 'string' || reason.length > 1024)) throw new RangeError('reason must be a string of at most 1024 characters');
    await HSETNX.run(this.redis, [this.key], [mandateId, JSON.stringify({ at: Date.now(), ...(reason !== undefined ? { reason } : {}) })]);
  }

  async unrevoke(mandateId: string): Promise<void> {
    validateMandateId(mandateId);
    await HDEL.run(this.redis, [this.key], [mandateId]);
  }

  async isRevoked(mandateId: string): Promise<boolean> {
    validateMandateId(mandateId);
    return Number(await HEXISTS.run(this.redis, [this.key], [mandateId])) === 1;
  }
}

/** Request sessions with a TTL; see {@link MandateSessionStore}. */
export class RedisMandateSessionStore implements MandateSessionStore {
  private readonly base: string;
  /** Default lifetime of a stored request session, in seconds. */
  readonly retentionSeconds: number;

  constructor(
    private readonly redis: RedisClient,
    opts: { prefix?: string; ttlSeconds?: number } = {},
  ) {
    this.base = `${checkPrefix(opts.prefix)}:request-session:`;
    this.retentionSeconds = durationSeconds('ttlSeconds', opts.ttlSeconds, 600);
  }

  /** Ids are hashed into keys, so a caller-chosen id cannot inject a hash tag or grow keys. */
  private k(id: string): string {
    validateSessionId(id);
    return this.base + sha256(id);
  }

  async put(id: string, session: MandateRequestSession, ttlSeconds?: number): Promise<void> {
    const key = this.k(id);
    const ttl = durationSeconds('ttlSeconds', ttlSeconds, this.retentionSeconds);
    const r = await this.redis.setNxPx(key, await serializeSession(session), Math.max(1, Math.round(ttl * 1000)));
    if (r !== 'OK') throw new Error('a live session with this id already exists');
  }

  async get(id: string): Promise<MandateRequestSession | undefined> {
    const r = await GET.run(this.redis, [this.k(id)], []);
    return typeof r === 'string' ? deserializeSession(r) : undefined;
  }

  async delete(id: string): Promise<void> {
    await DEL.run(this.redis, [this.k(id)], []);
  }
}
