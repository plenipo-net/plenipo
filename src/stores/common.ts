/**
 * Pieces shared by the Postgres and Redis stores: input validation (every value that reaches a store
 * may come from the network), and the serialisation of OpenID4VP request sessions.
 */
import { exportJWK, importJWK, type CryptoKey, type JWK } from 'jose';
import { sha256 } from '../encoding.js';
import { legalPrincipalProblems, REPRESENTATION_QUERY_ID } from '../legal.js';
import type { MandateRequestSession } from '../openid4vp.js';
import type { LedgerEntry, RevocationRegistry } from '../registry.js';
import { SCA_QUERY_ID } from '../root.js';
import { validateMandate } from '../scope.js';
import type { Amount, Mandate } from '../types.js';

/** A chain is at most 6 mandates; anything far above that is a bug or an attack. */
export const MAX_LEDGER_ENTRIES = 32;
/** Mandate keys are base64url SHA-256 hashes (43 characters); this leaves room for other key schemes. */
export const MAX_KEY_LENGTH = 256;
export const MAX_MANDATE_ID_LENGTH = 1024;
export const MAX_STATE_LENGTH = 512;
const CURRENCY_RE = /^[A-Z]{3}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
/** One year: a longer retention or TTL is almost certainly a unit mistake (milliseconds for seconds). */
const MAX_DURATION_SECONDS = 366 * 24 * 3600;

/** A revocation registry that can also be written to, e.g. by an operator console or a revocation API. */
export interface ManagedRevocationRegistry extends RevocationRegistry {
  /** Revokes a mandate by id. Revoking twice keeps the first revocation time. */
  revoke(mandateId: string, reason?: string): Promise<void>;
  /** Lifts a revocation. Meant for mistakes and suspensions; a revoked mandate normally stays revoked. */
  unrevoke(mandateId: string): Promise<void>;
  isRevoked(mandateId: string): Promise<boolean>;
}

/**
 * Keeps OpenID4VP request sessions between `createMandateRequest` and the wallet's POST, so the response
 * can land on any instance. Reading does not consume: single use is enforced by the `sessions` nonce store
 * of `handleMandateResponse`, because an error response must not burn the session.
 */
export interface MandateSessionStore {
  /**
   * Stores a session under a lookup id the platform chooses. With encrypted responses the `state` is
   * inside the JWE, so use an id the wallet echoes in the clear: a per-request path segment of the
   * response_uri, for example.
   */
  put(id: string, session: MandateRequestSession, ttlSeconds?: number): Promise<void>;
  /** The session, or undefined when unknown or expired. */
  get(id: string): Promise<MandateRequestSession | undefined>;
  delete(id: string): Promise<void>;
  /**
   * Default lifetime of a stored session, in seconds. A session that expires before the request's
   * `maxAgeSeconds` only makes late answers fail; it never weakens single use.
   */
  readonly retentionSeconds?: number;
}

/**
 * `expired_spent`: the sweep found the reservation still pending after its TTL. Its outcome is unknown,
 * so it counts as spent until a reconciliation says the action did not run. `expired` only appears in
 * rows written by schema version 1, whose sweep gave the amount back.
 */
export type ReservationState = 'pending' | 'committed' | 'released' | 'expired_spent' | 'expired';

/** What a reconciliation established about the action behind a reservation. */
export type ReconcileOutcome = 'executed' | 'not_executed';

/** What a store knows about a reservation, for operators and audits. */
export interface ReservationInfo {
  id: string;
  state: ReservationState;
  keys: string[];
  currency: string;
  amount: number;
  createdAt: Date;
  expiresAt: Date;
  settledAt?: Date;
  /** For a reservation that was released (now or before a correction): by `release` or by a reconciliation. */
  releasedBy?: 'release' | 'reconcile';
  /**
   * Set when a released reservation was later committed (a late commit, or `reconcile(id, 'executed')`):
   * the amount was counted again, possibly putting spending over a total, because the action did run.
   */
  correctedAt?: Date;
}

export interface NormalizedEntries {
  /** Unique keys, sorted by UTF-16 code unit. */
  keys: string[];
  /** Total per key, null when the mandate has no total. */
  totals: (number | null)[];
}

/**
 * Validates the ledger entries and merges duplicate keys. A key that appears twice is one mandate:
 * the amount is counted once against it, and the tighter total applies.
 */
export function normalizeEntries(entries: LedgerEntry[]): NormalizedEntries {
  if (!Array.isArray(entries) || entries.length === 0 || entries.length > MAX_LEDGER_ENTRIES) {
    throw new RangeError(`ledger entries must be an array of 1 to ${MAX_LEDGER_ENTRIES} items`);
  }
  const merged = new Map<string, number | null>();
  for (const e of entries) {
    if (typeof e !== 'object' || e === null) throw new TypeError('ledger entry must be an object');
    if (typeof e.key !== 'string' || e.key.length === 0 || e.key.length > MAX_KEY_LENGTH) {
      throw new RangeError(`ledger key must be a string of 1 to ${MAX_KEY_LENGTH} characters`);
    }
    let total: number | null = null;
    if (e.total !== undefined) {
      if (!isMinorUnits(e.total)) throw new RangeError('ledger total must be a non-negative safe integer');
      total = e.total;
    }
    const prev = merged.get(e.key);
    if (prev === undefined) merged.set(e.key, total);
    else if (total !== null && (prev === null || total < prev)) merged.set(e.key, total);
  }
  const keys = [...merged.keys()].sort();
  return { keys, totals: keys.map((k) => merged.get(k) ?? null) };
}

export function isMinorUnits(v: unknown): v is number {
  return typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
}

export function validateAmount(amount: Amount): void {
  if (typeof amount !== 'object' || amount === null) throw new TypeError('amount must be an object');
  if (!isMinorUnits(amount.value)) throw new RangeError('amount.value must be a non-negative safe integer in minor units');
  validateCurrency(amount.currency);
}

export function validateCurrency(currency: unknown): asserts currency is string {
  if (typeof currency !== 'string' || !CURRENCY_RE.test(currency)) throw new RangeError('currency must be an ISO 4217 code');
}

export function validateKey(key: unknown): asserts key is string {
  if (typeof key !== 'string' || key.length === 0 || key.length > MAX_KEY_LENGTH) {
    throw new RangeError(`ledger key must be a string of 1 to ${MAX_KEY_LENGTH} characters`);
  }
}

export function validateMandateId(id: unknown): asserts id is string {
  if (typeof id !== 'string' || id.length === 0 || id.length > MAX_MANDATE_ID_LENGTH) {
    throw new RangeError(`mandate id must be a string of 1 to ${MAX_MANDATE_ID_LENGTH} characters`);
  }
}

export function validateSessionId(id: unknown): asserts id is string {
  if (typeof id !== 'string' || id.length === 0 || id.length > MAX_STATE_LENGTH) {
    throw new RangeError(`session id must be a string of 1 to ${MAX_STATE_LENGTH} characters`);
  }
}

/** Reservation ids are UUIDs this library generated; anything else cannot be one of ours. */
export function isReservationId(id: unknown): id is string {
  return typeof id === 'string' && UUID_RE.test(id);
}

/** Validates a configured duration in seconds; fractions are allowed so tests can run fast. */
export function durationSeconds(name: string, value: number | undefined, fallback: number): number {
  const v = value ?? fallback;
  if (typeof v !== 'number' || !Number.isFinite(v) || v <= 0 || v > MAX_DURATION_SECONDS) {
    throw new RangeError(`${name} must be a number of seconds between 0 (excluded) and ${MAX_DURATION_SECONDS}`);
  }
  return v;
}

export function positiveInt(name: string, value: number | undefined, fallback: number, max = 1_000_000): number {
  const v = value ?? fallback;
  if (!Number.isSafeInteger(v) || v < 1 || v > max) throw new RangeError(`${name} must be an integer between 1 and ${max}`);
  return v;
}

/**
 * Nonces are stored as hashes: fixed size whatever the caller sent, and no attacker-chosen bytes
 * in keys or indexes. A nonce that is not a usable string can never be consumed.
 */
export function nonceDigest(nonce: unknown, maxLength = MAX_STATE_LENGTH): string | undefined {
  if (typeof nonce !== 'string' || nonce.length === 0 || nonce.length > maxLength) return undefined;
  return sha256(nonce);
}

/**
 * Converts a numeric column or reply to a safe integer. Drivers return BIGINT as string (pg), bigint
 * (PGlite) or number; a value that is not an exact safe integer is treated as corruption.
 */
export function toSafeInteger(v: unknown, what = 'value'): number {
  let n: number;
  if (typeof v === 'number') n = v;
  else if (typeof v === 'bigint') n = Number(v);
  else if (typeof v === 'string' && /^-?\d+$/.test(v)) n = Number(v);
  else throw new TypeError(`${what} is not an integer`);
  if (!Number.isSafeInteger(n) || (typeof v !== 'number' && BigInt(n) !== BigInt(v as string | bigint))) {
    throw new RangeError(`${what} is outside the safe integer range`);
  }
  return n;
}

/**
 * The retention a nonce store needs for a verifier configuration: an invocation is accepted from
 * `iat - skew` to `iat + maxAge`, so its nonce must be remembered for at least `maxAge + skew`.
 * The margin covers clock differences between verifier instances and the store.
 */
export function nonceRetentionSeconds(opts: { maxInvocationAgeSeconds?: number; skewSeconds?: number; marginSeconds?: number } = {}): number {
  return (opts.maxInvocationAgeSeconds ?? 120) + (opts.skewSeconds ?? 60) + (opts.marginSeconds ?? 60);
}

/**
 * Query ids a session may list in `extraQueries`: the ones `createMandateRequest` adds. Anything else in
 * a stored session would make `handleMandateResponse` demand a presentation nobody asked the wallet for.
 */
const KNOWN_EXTRA_QUERIES: ReadonlySet<string> = new Set([SCA_QUERY_ID, REPRESENTATION_QUERY_ID]);

/** Version 2 adds `mandate` (TS12 e-mandates) and `extraQueries` (SCA and representation attestations). */
const SESSION_FORMAT = 2;

interface SerializedSession {
  v: 1 | 2;
  clientId: string;
  nonce: string;
  state: string;
  transactionData: string;
  mandateId: string;
  responseMode: 'direct_post' | 'direct_post.jwt';
  createdAt: number;
  decryptionKey?: JWK;
  mandate?: Mandate;
  extraQueries?: string[];
}

/**
 * Serialises a request session. The decryption key is exported as a private JWK: whoever can read the
 * store can decrypt the wallet's response for this request until the session is deleted.
 */
export async function serializeSession(session: MandateRequestSession): Promise<string> {
  const s: SerializedSession = {
    v: SESSION_FORMAT,
    clientId: session.clientId,
    nonce: session.nonce,
    state: session.state,
    transactionData: session.transactionData,
    mandateId: session.mandateId,
    responseMode: session.responseMode,
    createdAt: session.createdAt,
  };
  if (session.decryptionKey) {
    const jwk = await exportJWK(session.decryptionKey);
    s.decryptionKey = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, d: jwk.d };
  }
  if (session.mandate !== undefined) {
    checkStoredMandate(session.mandate, session.mandateId);
    s.mandate = session.mandate;
  }
  if (session.extraQueries !== undefined) s.extraQueries = checkExtraQueries(session.extraQueries);
  return JSON.stringify(s);
}

/**
 * Shape check only: the lifetime policy and everything else about the mandate are enforced when the
 * response is verified. The mandate must be the one the request was made for.
 */
function checkStoredMandate(m: unknown, mandateId: string): Mandate {
  const problems = validateMandate(m, { maxLifetimeSeconds: Number.MAX_SAFE_INTEGER });
  const x = m as Mandate;
  if (!problems.length && x.principal !== undefined) problems.push(...legalPrincipalProblems(x.principal));
  if (problems.length) throw new TypeError(`stored session mandate is invalid: ${problems.join('; ')}`);
  if (x.id !== mandateId) throw new TypeError('stored session mandate is not the requested mandate');
  return x;
}

function checkExtraQueries(q: unknown): string[] {
  if (!Array.isArray(q) || q.length > KNOWN_EXTRA_QUERIES.size || new Set(q).size !== q.length) {
    throw new TypeError('stored session extraQueries must be a list of distinct query ids');
  }
  for (const id of q) {
    if (typeof id !== 'string' || !KNOWN_EXTRA_QUERIES.has(id)) throw new TypeError(`stored session lists an unknown query id ${String(id)}`);
  }
  return [...q];
}

/** Reads version 2, and version 1 written before e-mandates and legal-person roots existed. */
export async function deserializeSession(text: string): Promise<MandateRequestSession> {
  let s: SerializedSession;
  try {
    s = JSON.parse(text) as SerializedSession;
  } catch {
    throw new TypeError('stored session is not valid JSON');
  }
  const strings = ['clientId', 'nonce', 'state', 'transactionData', 'mandateId'] as const;
  if (typeof s !== 'object' || s === null || (s.v !== 1 && s.v !== 2) || strings.some((k) => typeof s[k] !== 'string')) {
    throw new TypeError('stored session has an unexpected shape');
  }
  if (s.responseMode !== 'direct_post' && s.responseMode !== 'direct_post.jwt') throw new TypeError('stored session has an unknown response mode');
  if (!Number.isSafeInteger(s.createdAt)) throw new TypeError('stored session has no creation time');
  if (s.v === 1 && (s.mandate !== undefined || s.extraQueries !== undefined)) throw new TypeError('stored session has members its version does not define');
  const mandate = s.mandate !== undefined ? checkStoredMandate(s.mandate, s.mandateId) : undefined;
  const extraQueries = s.extraQueries !== undefined ? checkExtraQueries(s.extraQueries) : undefined;
  let decryptionKey: CryptoKey | undefined;
  if (s.decryptionKey !== undefined) {
    const k = s.decryptionKey;
    if (k.kty !== 'EC' || k.crv !== 'P-256' || typeof k.d !== 'string') throw new TypeError('stored session key is not a P-256 private key');
    decryptionKey = (await importJWK(k, 'ECDH-ES', { extractable: true })) as CryptoKey;
  }
  if (s.responseMode === 'direct_post.jwt' && !decryptionKey) throw new TypeError('stored session lacks its decryption key');
  return {
    clientId: s.clientId,
    nonce: s.nonce,
    state: s.state,
    transactionData: s.transactionData,
    mandateId: s.mandateId,
    responseMode: s.responseMode,
    createdAt: s.createdAt,
    ...(decryptionKey ? { decryptionKey } : {}),
    ...(mandate ? { mandate } : {}),
    ...(extraQueries ? { extraQueries } : {}),
  };
}
