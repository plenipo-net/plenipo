/**
 * Idempotency keys for invocations.
 *
 * An agent that does not learn the outcome of a call (a timeout, a crash of its host) cannot reuse the
 * signed invocation: its nonce is single use and it goes stale after `maxInvocationAgeSeconds`. Without a
 * key, the retry is a new invocation and the service runs the action twice. With a key, the agent puts the
 * same `idem` in every attempt of one intention, each attempt still with its own nonce and `iat`, and the
 * verifier lets at most one attempt reach the action:
 *
 * - the key is free: the attempt claims it and proceeds;
 * - the key was used for a different request: `IDEMPOTENCY_CONFLICT`;
 * - an attempt holding the key is still running: `IDEMPOTENCY_IN_PROGRESS`;
 * - an attempt ended with an unknown outcome, or was abandoned: `IDEMPOTENCY_UNRESOLVED`, until a
 *   reconciliation (of the attempt, or of its ledger reservation) says whether it ran;
 * - an attempt executed: `ALREADY_EXECUTED`, with the stored result when the service kept one.
 *
 * The key is signed inside the invocation, so nobody between the agent and the service can change it, and
 * it is scoped to the service audience and the mandate chain, so two agents cannot collide or block each
 * other's keys.
 */
import { randomUUID } from 'node:crypto';
import { canonicalize, sha256 } from './encoding.js';
import type { InvocationPayload } from './types.js';

/** Syntax of an idempotency key: 16 to 128 characters of the base64url alphabet. A UUID without dashes fits. */
export const IDEMPOTENCY_KEY_RE = /^[A-Za-z0-9_-]{16,128}$/;

/** Default bound on a stored result, in bytes of its UTF-8 text. Larger results are not kept for replay. */
export const DEFAULT_MAX_REPLAY_BYTES = 64 * 1024;

/** Hard bound a store accepts for a stored result, whatever the caller asks. */
export const MAX_STORED_RESULT_BYTES = 256 * 1024;

/**
 * `in_progress`: an attempt holds the key and is running. `unknown`: an attempt ended without knowing
 * whether the action ran, or stayed `in_progress` longer than the store's lease. `executed`: it ran.
 */
export type IdempotencyState = 'in_progress' | 'unknown' | 'executed';

/** How an attempt ended. `not_executed` frees the key: the action certainly did not run. */
export type AttemptOutcome = 'executed' | 'not_executed' | 'unknown';

export interface IdempotencyRecord {
  /** The scoped key (see `idempotencyScope`). */
  key: string;
  /** What the key was first used for (see `requestFingerprint`). */
  fingerprint: string;
  state: IdempotencyState;
  /** Id of the attempt that holds the key. */
  attempt: string;
  /** Ledger reservation of that attempt, when it reserved spending. */
  reservation?: string;
  /** The result the service stored for replays, as opaque text. Absent when none was kept. */
  result?: string;
}

export type IdempotencyClaim = { claimed: true; attempt: string } | { claimed: false; record: IdempotencyRecord };

/**
 * Where a service keeps idempotency keys. Every operation is atomic: under concurrency exactly one
 * `claim` of a free key succeeds, across processes for a shared store.
 *
 * Records of executed attempts are kept for `retentionSeconds`, after which a retry runs again. Records of
 * attempts whose outcome is not known are never forgotten: they block the key until resolved.
 */
export interface IdempotencyStore {
  /** Claims a free key for a new attempt, or returns the record that holds it. */
  claim(key: string, fingerprint: string): Promise<IdempotencyClaim>;
  /** Records the ledger reservation of the attempt holding the key. No effect when another attempt holds it. */
  attach(key: string, attempt: string, reservation: string): Promise<void>;
  /**
   * Ends an attempt. `executed` keeps the record, with `result` for replays; it also applies when the key
   * was freed in the meantime and nobody claimed it again, because proof that the action ran wins.
   * `not_executed` frees the key, which a later `claim` can take.
   * `unknown` leaves the key blocked until `resolve`. No effect on a key held by another attempt, and an
   * executed record is final.
   */
  finish(key: string, attempt: string, outcome: AttemptOutcome, result?: string): Promise<void>;
  /**
   * Reconciliation of a key whose attempt is `in_progress` or `unknown`: `executed` marks it executed (with
   * no stored result), `not_executed` frees it. Only when `attempt` still holds the key: an outcome learned
   * about one attempt must never settle a newer one. Returns whether the record changed.
   */
  resolve(key: string, outcome: 'executed' | 'not_executed', attempt: string): Promise<boolean>;
  get(key: string): Promise<IdempotencyRecord | undefined>;
  /**
   * Records blocked on an unknown outcome (including abandoned attempts), for a reconciliation job. Each
   * names its attempt: pass it to `resolve`.
   */
  unresolved(opts?: { limit?: number }): Promise<IdempotencyRecord[]>;
  /** How long an executed record is kept, in seconds. */
  readonly retentionSeconds: number;
  /** How long an attempt may stay `in_progress` before it counts as abandoned (`unknown`), in seconds. */
  readonly leaseSeconds: number;
}

/**
 * The key under which a service stores an invocation's `idem`: bound to the service audience and to the
 * whole mandate chain, so keys of different agents, people or services never meet.
 */
export function idempotencyScope(audience: string, chainHashValue: string, idem: string): string {
  return sha256(canonicalize({ typ: 'plenipo-idempotency', aud: audience, chain: chainHashValue, idem }));
}

/**
 * What an attempt does, for comparing attempts that share a key: action, counterparty, amount and the
 * argument hash. Nonce and `iat` are left out, since every attempt has its own.
 */
export function requestFingerprint(inv: Pick<InvocationPayload, 'action' | 'counterparty' | 'amount' | 'args_hash'>): string {
  return sha256(
    canonicalize({
      action: inv.action,
      ...(inv.counterparty !== undefined ? { counterparty: inv.counterparty } : {}),
      ...(inv.amount !== undefined ? { amount: { value: inv.amount.value, currency: inv.amount.currency } } : {}),
      ...(inv.args_hash !== undefined ? { args_hash: inv.args_hash } : {}),
    }),
  );
}

/** A fresh idempotency key for one intention of an agent: 32 characters, from a random UUID. */
export function newIdempotencyKey(): string {
  return randomUUID().replaceAll('-', '');
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const MAX_KEY_LENGTH = 256;
/** One year: a longer duration is almost certainly a unit mistake. */
const MAX_DURATION_SECONDS = 366 * 24 * 3600;

/** Input checks shared by every store: values may come from anywhere. */
export function validateIdempotencyKey(key: unknown): asserts key is string {
  if (typeof key !== 'string' || key.length === 0 || key.length > MAX_KEY_LENGTH) {
    throw new RangeError(`idempotency key must be a string of 1 to ${MAX_KEY_LENGTH} characters`);
  }
}

export function validateFingerprint(fp: unknown): asserts fp is string {
  if (typeof fp !== 'string' || fp.length === 0 || fp.length > MAX_KEY_LENGTH) {
    throw new RangeError(`fingerprint must be a string of 1 to ${MAX_KEY_LENGTH} characters`);
  }
}

export function isAttemptId(x: unknown): x is string {
  return typeof x === 'string' && UUID_RE.test(x);
}

export function validateOutcome(o: unknown): asserts o is AttemptOutcome {
  if (o !== 'executed' && o !== 'not_executed' && o !== 'unknown') throw new RangeError('outcome must be executed, not_executed or unknown');
}

export function validateResult(result: unknown): asserts result is string | undefined {
  if (result === undefined) return;
  if (typeof result !== 'string') throw new TypeError('result must be a string');
  if (Buffer.byteLength(result, 'utf8') > MAX_STORED_RESULT_BYTES) throw new RangeError(`result exceeds ${MAX_STORED_RESULT_BYTES} bytes`);
}

export function idempotencyDuration(name: string, value: number | undefined, fallback: number): number {
  const v = value ?? fallback;
  if (typeof v !== 'number' || !Number.isFinite(v) || v <= 0 || v > MAX_DURATION_SECONDS) {
    throw new RangeError(`${name} must be a number of seconds between 0 (excluded) and ${MAX_DURATION_SECONDS}`);
  }
  return v;
}

export interface IdempotencyStoreOptions {
  /** How long an executed record is kept, in seconds. Default 86400 (one day). */
  retentionSeconds?: number;
  /**
   * How long an attempt may stay `in_progress` before it counts as abandoned, in seconds. Must exceed the
   * longest time between ALLOW and the end of the action. Default 300.
   */
  leaseSeconds?: number;
}

/** The in-memory store sweeps expired records at most this often, in milliseconds (or each retention period). */
const SWEEP_INTERVAL_MS = 60_000;

interface MemoryEntry {
  fingerprint: string;
  /** `free`: the attempt certainly did not run; the key can be claimed again. Kept so a late "executed" still lands. */
  state: 'in_progress' | 'unknown' | 'executed' | 'free';
  attempt: string;
  reservation?: string;
  result?: string;
  /** Milliseconds: lease end for in_progress, expiry for executed and free, unused for unknown. */
  until: number;
}

/**
 * In-memory store for development, tests and single-process services. Operations are synchronous inside,
 * so they are atomic within one Node.js process.
 */
export class InMemoryIdempotencyStore implements IdempotencyStore {
  readonly retentionSeconds: number;
  readonly leaseSeconds: number;
  private readonly entries = new Map<string, MemoryEntry>();
  private readonly clock: () => number;
  private nextSweep = 0;

  constructor(opts: IdempotencyStoreOptions & { /** Clock in milliseconds, for tests. */ now?: () => number } = {}) {
    this.retentionSeconds = idempotencyDuration('retentionSeconds', opts.retentionSeconds, 24 * 3600);
    this.leaseSeconds = idempotencyDuration('leaseSeconds', opts.leaseSeconds, 300);
    this.clock = opts.now ?? Date.now;
  }

  /** Deletes executed and free records past their retention. Returns how many were deleted. */
  sweep(): number {
    const now = this.clock();
    let n = 0;
    for (const [k, e] of this.entries) {
      if ((e.state === 'executed' || e.state === 'free') && e.until <= now) {
        this.entries.delete(k);
        n++;
      }
    }
    return n;
  }

  /** The entry with time applied: expired records dropped, abandoned attempts turned unknown. */
  private current(key: string): MemoryEntry | undefined {
    // Amortised: records nobody touches again would otherwise stay forever.
    const t = this.clock();
    if (t >= this.nextSweep) {
      this.nextSweep = t + Math.min(SWEEP_INTERVAL_MS, this.retentionSeconds * 1000);
      this.sweep();
    }
    const e = this.entries.get(key);
    if (!e) return undefined;
    const now = this.clock();
    if ((e.state === 'executed' || e.state === 'free') && e.until <= now) {
      this.entries.delete(key);
      return undefined;
    }
    if (e.state === 'in_progress' && e.until <= now) e.state = 'unknown';
    return e;
  }

  private view(key: string, e: MemoryEntry): IdempotencyRecord {
    return {
      key,
      fingerprint: e.fingerprint,
      state: e.state as IdempotencyState,
      attempt: e.attempt,
      ...(e.reservation !== undefined ? { reservation: e.reservation } : {}),
      ...(e.result !== undefined ? { result: e.result } : {}),
    };
  }

  async claim(key: string, fingerprint: string): Promise<IdempotencyClaim> {
    validateIdempotencyKey(key);
    validateFingerprint(fingerprint);
    const held = this.current(key);
    if (held && held.state !== 'free') return { claimed: false, record: this.view(key, held) };
    const attempt = randomUUID();
    this.entries.set(key, { fingerprint, state: 'in_progress', attempt, until: this.clock() + this.leaseSeconds * 1000 });
    return { claimed: true, attempt };
  }

  async attach(key: string, attempt: string, reservation: string): Promise<void> {
    validateIdempotencyKey(key);
    if (!isAttemptId(attempt) || typeof reservation !== 'string' || reservation.length === 0 || reservation.length > MAX_KEY_LENGTH) return;
    const e = this.current(key);
    if (e && e.attempt === attempt && (e.state === 'in_progress' || e.state === 'unknown')) e.reservation = reservation;
  }

  async finish(key: string, attempt: string, outcome: AttemptOutcome, result?: string): Promise<void> {
    validateIdempotencyKey(key);
    validateOutcome(outcome);
    validateResult(result);
    if (!isAttemptId(attempt)) return;
    const e = this.current(key);
    if (!e || e.attempt !== attempt || e.state === 'executed') return;
    const now = this.clock();
    if (outcome === 'executed') {
      // Also from `free`: proof that the action ran wins over an earlier "did not run".
      e.state = 'executed';
      if (result !== undefined) e.result = result;
      e.until = now + this.retentionSeconds * 1000;
    } else if (e.state === 'free') {
      return;
    } else if (outcome === 'not_executed') {
      e.state = 'free';
      delete e.result;
      e.until = now + this.retentionSeconds * 1000;
    } else {
      e.state = 'unknown';
    }
  }

  async resolve(key: string, outcome: 'executed' | 'not_executed', attempt: string): Promise<boolean> {
    validateIdempotencyKey(key);
    if (outcome !== 'executed' && outcome !== 'not_executed') throw new RangeError('outcome must be executed or not_executed');
    if (!isAttemptId(attempt)) throw new RangeError('resolve needs the attempt that holds the key');
    const e = this.current(key);
    if (!e || e.attempt !== attempt || (e.state !== 'in_progress' && e.state !== 'unknown')) return false;
    e.state = outcome === 'executed' ? 'executed' : 'free';
    e.until = this.clock() + this.retentionSeconds * 1000;
    return true;
  }

  async get(key: string): Promise<IdempotencyRecord | undefined> {
    validateIdempotencyKey(key);
    const e = this.current(key);
    return e && e.state !== 'free' ? this.view(key, e) : undefined;
  }

  async unresolved(opts: { limit?: number } = {}): Promise<IdempotencyRecord[]> {
    const limit = opts.limit ?? 100;
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 10_000) throw new RangeError('limit must be an integer between 1 and 10000');
    const out: IdempotencyRecord[] = [];
    for (const key of [...this.entries.keys()]) {
      if (out.length >= limit) break;
      const e = this.current(key);
      if (e?.state === 'unknown') out.push(this.view(key, e));
    }
    return out;
  }
}
