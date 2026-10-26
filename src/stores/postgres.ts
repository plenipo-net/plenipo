/**
 * Postgres implementations of the stateful interfaces, so several verifier instances can share
 * spending, nonces, idempotency keys, revocations and OpenID4VP sessions.
 *
 * No driver is imported: every store takes a {@link SqlClient}, which a `pg` Pool or Client and a
 * PGlite instance satisfy as they are. Every operation is a single SQL statement, so a pool can run it
 * on any connection and no transaction is ever left open by a crashed caller.
 */
import { createHash, randomUUID } from 'node:crypto';
import type { MandateRequestSession } from '../openid4vp.js';
import type { LedgerEntry, NonceStore, SpendingLedger } from '../registry.js';
import type { Amount } from '../types.js';
import {
  idempotencyDuration,
  isAttemptId,
  validateFingerprint,
  validateIdempotencyKey,
  validateOutcome,
  validateResult,
  type AttemptOutcome,
  type IdempotencyClaim,
  type IdempotencyRecord,
  type IdempotencyState,
  type IdempotencyStore,
  type IdempotencyStoreOptions,
} from '../idempotency.js';
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

/** The part of a Postgres driver the stores use. `pg` Pool, `pg` Client and PGlite fit as they are. */
export interface SqlClient {
  query(text: string, params?: unknown[]): Promise<{ rows: unknown[] }>;
}

export interface PostgresNamingOptions {
  /** Prefix of every table, index and function. Lower case letters, digits and `_`. Default `plenipo_`. */
  tablePrefix?: string;
  /** Schema that holds the objects; default the connection's search_path. */
  schema?: string;
}

const IDENT_RE = /^[a-z_][a-z0-9_]{0,39}$/;
/** Bumped when the schema changes; recorded so a future migration knows where it starts from. */
export const POSTGRES_SCHEMA_VERSION = 4;

interface Names {
  ledger: string;
  reservations: string;
  nonces: string;
  revocations: string;
  sessions: string;
  idempotency: string;
  meta: string;
  reserve: string;
  settle: string;
  expire: string;
  upgrade: string;
  /** Unqualified prefix, for index names (which always live in the table's schema). */
  prefix: string;
  lockKey: string;
}

/** Identifiers are interpolated into SQL, so they are validated against a strict pattern first. */
function names(opts: PostgresNamingOptions = {}): Names {
  const prefix = opts.tablePrefix ?? 'plenipo_';
  if (prefix !== '' && !/^[a-z_][a-z0-9_]{0,29}$/.test(prefix)) {
    throw new RangeError('tablePrefix must match /^[a-z_][a-z0-9_]{0,29}$/');
  }
  if (opts.schema !== undefined && !IDENT_RE.test(opts.schema)) throw new RangeError('schema must match /^[a-z_][a-z0-9_]{0,39}$/');
  const q = (n: string) => (opts.schema ? `${opts.schema}.${prefix}${n}` : `${prefix}${n}`);
  // Advisory lock id for migrations: stable per schema and prefix, a signed 64-bit integer.
  const lockKey = createHash('sha256').update(`plenipo-migrate:${opts.schema ?? ''}:${prefix}`).digest().readBigInt64BE(0).toString();
  return {
    ledger: q('ledger'),
    reservations: q('reservations'),
    nonces: q('nonces'),
    revocations: q('revocations'),
    sessions: q('request_sessions'),
    idempotency: q('idempotency'),
    meta: q('schema_meta'),
    reserve: q('ledger_reserve'),
    settle: q('ledger_settle'),
    expire: q('ledger_expire'),
    upgrade: q('schema_upgrade'),
    prefix,
    lockKey,
  };
}

function statements(n: Names): string[] {
  return [
    `CREATE TABLE IF NOT EXISTS ${n.meta} (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  version INTEGER NOT NULL
)`,
    `INSERT INTO ${n.meta} (id, version) VALUES (1, ${POSTGRES_SCHEMA_VERSION}) ON CONFLICT (id) DO NOTHING`,
    // Spending per mandate key and currency, in minor units. Byte-order collation makes the lock
    // order identical in every function, whatever the database locale.
    `CREATE TABLE IF NOT EXISTS ${n.ledger} (
  mandate_key TEXT COLLATE "C" NOT NULL CHECK (length(mandate_key) BETWEEN 1 AND 256),
  currency TEXT COLLATE "C" NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
  committed BIGINT NOT NULL DEFAULT 0 CHECK (committed >= 0),
  pending BIGINT NOT NULL DEFAULT 0 CHECK (pending >= 0),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (mandate_key, currency)
)`,
    `CREATE TABLE IF NOT EXISTS ${n.reservations} (
  id UUID PRIMARY KEY,
  mandate_keys TEXT[] NOT NULL,
  currency TEXT NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
  amount BIGINT NOT NULL CHECK (amount >= 0),
  state TEXT NOT NULL CONSTRAINT ${n.prefix}reservations_state_check
    CHECK (state IN ('pending', 'committed', 'released', 'expired_spent', 'expired')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ NOT NULL,
  settled_at TIMESTAMPTZ,
  released_by TEXT CHECK (released_by IN ('release', 'reconcile')),
  corrected_at TIMESTAMPTZ
)`,
    `CREATE INDEX IF NOT EXISTS ${n.prefix}reservations_pending_idx ON ${n.reservations} (expires_at) WHERE state = 'pending'`,
    `CREATE INDEX IF NOT EXISTS ${n.prefix}reservations_settled_idx ON ${n.reservations} (settled_at) WHERE state <> 'pending'`,
    `CREATE INDEX IF NOT EXISTS ${n.prefix}reservations_unresolved_idx ON ${n.reservations} (settled_at) WHERE state = 'expired_spent'`,
    // In-place upgrades from older versions. Each step runs once; a schema created at the current
    // version skips them all.
    `CREATE OR REPLACE FUNCTION ${n.upgrade}() RETURNS VOID LANGUAGE plpgsql AS $plenipo$
BEGIN
  IF (SELECT version FROM ${n.meta} WHERE id = 1) < 2 THEN
    ALTER TABLE ${n.reservations} DROP CONSTRAINT IF EXISTS ${n.prefix}reservations_state_check;
    ALTER TABLE ${n.reservations} ADD CONSTRAINT ${n.prefix}reservations_state_check
      CHECK (state IN ('pending', 'committed', 'released', 'expired_spent', 'expired'));
    UPDATE ${n.meta} SET version = 2 WHERE id = 1;
  END IF;
  -- Version 2 to 3: who released a reservation, and when a release was corrected by a later commit.
  IF (SELECT version FROM ${n.meta} WHERE id = 1) < 3 THEN
    ALTER TABLE ${n.reservations} ADD COLUMN IF NOT EXISTS released_by TEXT CHECK (released_by IN ('release', 'reconcile'));
    ALTER TABLE ${n.reservations} ADD COLUMN IF NOT EXISTS corrected_at TIMESTAMPTZ;
    UPDATE ${n.meta} SET version = 3 WHERE id = 1;
  END IF;
  -- Version 3 to 4: only a new table (idempotency keys), created below.
  IF (SELECT version FROM ${n.meta} WHERE id = 1) < 4 THEN
    UPDATE ${n.meta} SET version = 4 WHERE id = 1;
  END IF;
END
$plenipo$`,
    `SELECT ${n.upgrade}()`,
    `CREATE TABLE IF NOT EXISTS ${n.nonces} (
  namespace TEXT NOT NULL,
  nonce_hash TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  PRIMARY KEY (namespace, nonce_hash)
)`,
    `CREATE INDEX IF NOT EXISTS ${n.prefix}nonces_expiry_idx ON ${n.nonces} (expires_at)`,
    `CREATE TABLE IF NOT EXISTS ${n.revocations} (
  mandate_id TEXT PRIMARY KEY CHECK (length(mandate_id) BETWEEN 1 AND 1024),
  revoked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  reason TEXT CHECK (reason IS NULL OR length(reason) <= 1024)
)`,
    `CREATE TABLE IF NOT EXISTS ${n.sessions} (
  id TEXT PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 512),
  data TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL
)`,
    `CREATE INDEX IF NOT EXISTS ${n.prefix}request_sessions_expiry_idx ON ${n.sessions} (expires_at)`,
    // Idempotency keys. `free` keeps a released key until it expires, so a late "executed" still lands;
    // in_progress and unknown rows never expire: they block their key until reconciled.
    `CREATE TABLE IF NOT EXISTS ${n.idempotency} (
  key TEXT COLLATE "C" PRIMARY KEY CHECK (length(key) BETWEEN 1 AND 256),
  fingerprint TEXT NOT NULL CHECK (length(fingerprint) BETWEEN 1 AND 256),
  state TEXT NOT NULL CHECK (state IN ('in_progress', 'unknown', 'executed', 'free')),
  attempt UUID NOT NULL,
  reservation TEXT CHECK (reservation IS NULL OR length(reservation) BETWEEN 1 AND 256),
  result TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  lease_until TIMESTAMPTZ,
  expires_at TIMESTAMPTZ
)`,
    `CREATE INDEX IF NOT EXISTS ${n.prefix}idempotency_open_idx ON ${n.idempotency} (lease_until) WHERE state IN ('in_progress', 'unknown')`,
    `CREATE INDEX IF NOT EXISTS ${n.prefix}idempotency_expiry_idx ON ${n.idempotency} (expires_at) WHERE state IN ('executed', 'free')`,
    // Reserve: all or nothing over every entry of the chain. Rows are created and then locked in key
    // order, so two reservations over overlapping chains always queue instead of deadlocking.
    // Runs as one statement: in READ COMMITTED each query below sees the rows as last committed.
    `CREATE OR REPLACE FUNCTION ${n.reserve}(
  p_id UUID, p_keys TEXT[], p_totals BIGINT[], p_currency TEXT, p_amount BIGINT, p_ttl_seconds DOUBLE PRECISION
) RETURNS BOOLEAN LANGUAGE plpgsql AS $plenipo$
DECLARE
  k TEXT;
  r RECORD;
  n INTEGER;
BEGIN
  IF p_amount IS NULL OR p_amount < 0 THEN RAISE EXCEPTION 'plenipo: invalid amount'; END IF;
  n := coalesce(array_length(p_keys, 1), 0);
  IF n = 0 OR n <> coalesce(array_length(p_totals, 1), 0) THEN RAISE EXCEPTION 'plenipo: invalid ledger entries'; END IF;
  IF p_ttl_seconds IS NULL OR p_ttl_seconds <= 0 THEN RAISE EXCEPTION 'plenipo: invalid ttl'; END IF;
  FOR k IN SELECT DISTINCT u COLLATE "C" AS u FROM unnest(p_keys) AS u ORDER BY 1 LOOP
    INSERT INTO ${n.ledger} (mandate_key, currency) VALUES (k, p_currency) ON CONFLICT DO NOTHING;
  END LOOP;
  FOR r IN
    SELECT l.committed, l.pending, e.total
      FROM ${n.ledger} l
      JOIN unnest(p_keys, p_totals) AS e(k, total) ON l.mandate_key = e.k
     WHERE l.currency = p_currency
     ORDER BY l.mandate_key COLLATE "C"
       FOR UPDATE OF l
  LOOP
    IF r.total IS NOT NULL AND r.committed + r.pending + p_amount > r.total THEN
      RETURN FALSE;
    END IF;
  END LOOP;
  UPDATE ${n.ledger} SET pending = pending + p_amount, updated_at = now()
   WHERE currency = p_currency AND mandate_key = ANY (p_keys);
  INSERT INTO ${n.reservations} (id, mandate_keys, currency, amount, state, expires_at)
  VALUES (p_id, p_keys, p_currency, p_amount, 'pending', now() + make_interval(secs => p_ttl_seconds));
  RETURN TRUE;
END
$plenipo$`,
    // Settle, exactly once per transition. The reservation row is locked first, then the ledger rows in
    // key order. Evidence that the action ran always wins, because under-counting is the unsafe error:
    //   commit        pending -> committed (pending moves to committed); expired_spent -> committed
    //                 (already counted); released or expired (v1, amount given back) -> committed, the
    //                 amount counted again even if that puts spending over a total
    //   release       pending -> released. Never touches expired_spent: its outcome is unknown.
    //   not_executed  reconciliation: pending or expired_spent -> released, the amount is given back;
    //                 expired (v1, already given back) -> released
    // Anything else, including every attempt to give back a committed reservation, changes nothing.
    `CREATE OR REPLACE FUNCTION ${n.settle}(p_id UUID, p_action TEXT) RETURNS TEXT LANGUAGE plpgsql AS $plenipo$
DECLARE
  r RECORD;
  d_pending BIGINT := 0;
  d_committed BIGINT := 0;
  target TEXT;
  corrected BOOLEAN := FALSE;
BEGIN
  IF p_action NOT IN ('commit', 'release', 'not_executed') THEN RAISE EXCEPTION 'plenipo: invalid action'; END IF;
  SELECT * INTO r FROM ${n.reservations} WHERE id = p_id FOR UPDATE;
  IF NOT FOUND THEN RETURN 'unknown'; END IF;
  IF p_action = 'commit' AND r.state = 'pending' THEN
    d_pending := -r.amount; d_committed := r.amount; target := 'committed';
  ELSIF p_action = 'commit' AND r.state = 'expired_spent' THEN
    target := 'committed';
  ELSIF p_action = 'commit' AND r.state = 'expired' THEN
    d_committed := r.amount; target := 'committed';
  ELSIF p_action = 'commit' AND r.state = 'released' THEN
    d_committed := r.amount; target := 'committed'; corrected := TRUE;
  ELSIF p_action IN ('release', 'not_executed') AND r.state = 'pending' THEN
    d_pending := -r.amount; target := 'released';
  ELSIF p_action = 'not_executed' AND r.state = 'expired_spent' THEN
    d_committed := -r.amount; target := 'released';
  ELSIF p_action = 'not_executed' AND r.state = 'expired' THEN
    target := 'released';
  ELSE
    RETURN r.state;
  END IF;
  IF d_pending <> 0 OR d_committed <> 0 THEN
    PERFORM 1 FROM ${n.ledger}
      WHERE currency = r.currency AND mandate_key = ANY (r.mandate_keys)
      ORDER BY mandate_key COLLATE "C" FOR UPDATE;
    UPDATE ${n.ledger} SET pending = pending + d_pending, committed = committed + d_committed, updated_at = now()
     WHERE currency = r.currency AND mandate_key = ANY (r.mandate_keys);
  END IF;
  UPDATE ${n.reservations}
     SET state = target,
         settled_at = now(),
         released_by = CASE WHEN target = 'released'
                            THEN CASE WHEN p_action = 'release' THEN 'release' ELSE 'reconcile' END
                            ELSE released_by END,
         corrected_at = CASE WHEN corrected THEN now() ELSE corrected_at END
   WHERE id = p_id;
  RETURN target;
END
$plenipo$`,
    // Expire stale pending reservations as SPENT: their outcome is unknown, and the money may have moved.
    // The amount moves from pending to committed and stays in the totals until a reconciliation says
    // otherwise. Rows another session is settling are skipped, and the ledger is updated per key in key
    // order after aggregating, so the sweep never holds ledger locks in an order a reservation could invert.
    `CREATE OR REPLACE FUNCTION ${n.expire}(p_limit INTEGER) RETURNS INTEGER LANGUAGE plpgsql AS $plenipo$
DECLARE
  cnt INTEGER;
  ks TEXT[];
  cs TEXT[];
  ts BIGINT[];
BEGIN
  WITH stale AS (
    SELECT id FROM ${n.reservations}
     WHERE state = 'pending' AND expires_at <= now()
     ORDER BY expires_at
     LIMIT p_limit
       FOR UPDATE SKIP LOCKED
  ), done AS (
    UPDATE ${n.reservations} t SET state = 'expired_spent', settled_at = now()
      FROM stale WHERE t.id = stale.id
    RETURNING t.mandate_keys, t.currency, t.amount
  ), per_key AS (
    SELECT k COLLATE "C" AS k, d.currency, sum(d.amount)::bigint AS total
      FROM done d, unnest(d.mandate_keys) AS k
     GROUP BY 1, 2
  )
  SELECT (SELECT count(*) FROM done),
         array_agg(k ORDER BY k, currency),
         array_agg(currency ORDER BY k, currency),
         array_agg(total ORDER BY k, currency)
    INTO cnt, ks, cs, ts
    FROM per_key;
  FOR i IN 1 .. coalesce(array_length(ks, 1), 0) LOOP
    UPDATE ${n.ledger} SET pending = pending - ts[i], committed = committed + ts[i], updated_at = now()
     WHERE mandate_key = ks[i] AND currency = cs[i];
  END LOOP;
  RETURN cnt;
END
$plenipo$`,
  ];
}

/**
 * The schema as plain SQL, one statement after another, for psql or a migration tool.
 * Idempotent: every statement can run again on an existing schema.
 */
export function postgresSchema(opts: PostgresNamingOptions = {}): string {
  return `-- Plenipo shared stores, schema version ${POSTGRES_SCHEMA_VERSION}.\n${statements(names(opts))
    .map((s) => `${s};\n`)
    .join('\n')}`;
}

/** The schema with the default names, as shipped in src/stores/schema.sql. */
export const POSTGRES_SCHEMA_SQL = postgresSchema();

/**
 * Creates or updates the schema. Safe to call from every instance at start-up: it runs as one
 * statement under an advisory lock, so concurrent migrations wait for each other.
 */
export async function migratePostgres(db: SqlClient, opts: PostgresNamingOptions = {}): Promise<void> {
  const n = names(opts);
  // Inside the DO block a bare SELECT has nowhere to put its result; PL/pgSQL wants PERFORM.
  const body = statements(n)
    .map((s) => `${s.startsWith('SELECT ') ? `PERFORM ${s.slice(7)}` : s};`)
    .join('\n');
  await db.query(`DO $plenipo_migrate$\nBEGIN\nPERFORM pg_advisory_xact_lock(${n.lockKey});\n${body}\nEND\n$plenipo_migrate$`);
}

function rowsOf(res: { rows: unknown[] }): Record<string, unknown>[] {
  if (!res || !Array.isArray(res.rows)) throw new TypeError('the SQL client returned no rows array');
  return res.rows as Record<string, unknown>[];
}

function toDate(v: unknown): Date {
  const d = v instanceof Date ? v : new Date(String(v));
  if (Number.isNaN(d.getTime())) throw new TypeError('invalid timestamp from the database');
  return d;
}

export interface PostgresLedgerOptions extends PostgresNamingOptions {
  /**
   * How long a reservation may stay pending before {@link PostgresSpendingLedger.sweepExpired} releases
   * it, in seconds. Must exceed the longest time between ALLOW and commit. Default 900.
   */
  pendingTtlSeconds?: number;
}

/**
 * Spending ledger shared by every verifier instance on the same database. `reserve` is atomic across
 * processes over all entries of the chain; see the schema functions for the locking discipline.
 */
export class PostgresSpendingLedger implements SpendingLedger {
  private readonly n: Names;
  private readonly ttl: number;

  constructor(
    private readonly db: SqlClient,
    opts: PostgresLedgerOptions = {},
  ) {
    this.n = names(opts);
    this.ttl = durationSeconds('pendingTtlSeconds', opts.pendingTtlSeconds, 900);
  }

  async spent(key: string, currency: string): Promise<number> {
    validateKey(key);
    validateCurrency(currency);
    const rows = rowsOf(
      await this.db.query(`SELECT committed + pending AS spent FROM ${this.n.ledger} WHERE mandate_key = $1 AND currency = $2`, [key, currency]),
    );
    return rows.length ? toSafeInteger(rows[0].spent, 'spent') : 0;
  }

  async reserve(entries: LedgerEntry[], amount: Amount): Promise<string | null> {
    validateAmount(amount);
    const { keys, totals } = normalizeEntries(entries);
    const id = randomUUID();
    const rows = rowsOf(
      await this.db.query(
        `SELECT ${this.n.reserve}($1::uuid, $2::text[], $3::bigint[], $4::text, $5::bigint, $6::double precision) AS ok`,
        [id, keys, totals.map((t) => (t === null ? null : String(t))), amount.currency, String(amount.value), this.ttl],
      ),
    );
    return rows[0]?.ok === true ? id : null;
  }

  async commit(reservationId: string): Promise<void> {
    await this.settle(reservationId, 'commit');
  }

  async release(reservationId: string): Promise<void> {
    await this.settle(reservationId, 'release');
  }

  /**
   * Applies a commit or release and returns the reservation's state afterwards ('unknown' when there is
   * none). A release never gives back an `expired_spent` reservation; that takes {@link reconcile}.
   */
  async settle(reservationId: string, action: 'commit' | 'release'): Promise<ReservationState | 'unknown'> {
    if (action !== 'commit' && action !== 'release') throw new RangeError('action must be commit or release');
    return this.apply(reservationId, action);
  }

  /**
   * Records what a reconciliation (an operator, or a back-office job matching reservations against the
   * payment rail) established. `not_executed` gives the amount back for a `pending` or `expired_spent`
   * reservation. `executed` is a commit, and like a commit it also corrects a `released` reservation:
   * the amount is counted again (even beyond a total: the money did move) and `correctedAt` is set.
   * A committed reservation is never given back: the call returns its state unchanged. Returns the
   * state afterwards.
   */
  async reconcile(reservationId: string, outcome: ReconcileOutcome): Promise<ReservationState | 'unknown'> {
    if (outcome !== 'executed' && outcome !== 'not_executed') throw new RangeError('outcome must be executed or not_executed');
    return this.apply(reservationId, outcome === 'executed' ? 'commit' : 'not_executed');
  }

  private async apply(reservationId: string, action: 'commit' | 'release' | 'not_executed'): Promise<ReservationState | 'unknown'> {
    if (!isReservationId(reservationId)) return 'unknown';
    const rows = rowsOf(await this.db.query(`SELECT ${this.n.settle}($1::uuid, $2::text) AS state`, [reservationId, action]));
    return rows[0]?.state as ReservationState | 'unknown';
  }

  /**
   * Turns reservations still pending after their TTL into `expired_spent`: the verifier crashed, timed
   * out or lost its connection between ALLOW and the commit or release, so nobody knows whether the
   * action ran. The amount stays counted (it moves from pending to committed): a stuck reservation can
   * only reduce the available budget, never let spending exceed a total. Only {@link reconcile} gives it
   * back. Schedule it every minute or so; returns how many reservations it expired, call again while it
   * returns `limit`.
   */
  async sweepExpired(opts: { limit?: number } = {}): Promise<number> {
    const limit = positiveInt('limit', opts.limit, 1000);
    const rows = rowsOf(await this.db.query(`SELECT ${this.n.expire}($1::integer) AS n`, [limit]));
    return toSafeInteger(rows[0]?.n ?? 0, 'count');
  }

  /**
   * Deletes committed and released reservations settled more than `olderThanSeconds` ago. After that a
   * duplicate commit or release of them is a no-op, and a released one can no longer be corrected by a
   * late commit. `expired_spent` and legacy `expired` reservations are kept until they are reconciled;
   * `pending` ones until they settle or expire.
   */
  async purgeSettled(opts: { olderThanSeconds: number; limit?: number }): Promise<number> {
    const age = durationSeconds('olderThanSeconds', opts?.olderThanSeconds, 0);
    const limit = positiveInt('limit', opts.limit, 10_000);
    const rows = rowsOf(
      await this.db.query(
        `WITH gone AS (
           DELETE FROM ${this.n.reservations} WHERE id IN (
             SELECT id FROM ${this.n.reservations}
              WHERE state NOT IN ('pending', 'expired_spent', 'expired') AND settled_at < now() - make_interval(secs => $1::double precision)
              LIMIT $2::integer)
           RETURNING 1)
         SELECT count(*) AS n FROM gone`,
        [age, limit],
      ),
    );
    return toSafeInteger(rows[0]?.n ?? 0, 'count');
  }

  async reservation(reservationId: string): Promise<ReservationInfo | undefined> {
    if (!isReservationId(reservationId)) return undefined;
    const rows = rowsOf(
      await this.db.query(
        `SELECT id::text AS id, state, mandate_keys, currency, amount, created_at, expires_at, settled_at, released_by, corrected_at
           FROM ${this.n.reservations} WHERE id = $1::uuid`,
        [reservationId],
      ),
    );
    return rows.length ? reservationInfo(rows[0]) : undefined;
  }

  /**
   * The work list of a reconciliation job, oldest first: reservations the sweep counted as spent
   * (`expired_spent`) and legacy `expired` rows of schema version 1, whose amount was given back without
   * knowing whether the action ran.
   */
  async unresolved(opts: { limit?: number } = {}): Promise<ReservationInfo[]> {
    const limit = positiveInt('limit', opts.limit, 1000);
    const rows = rowsOf(
      await this.db.query(
        `SELECT id::text AS id, state, mandate_keys, currency, amount, created_at, expires_at, settled_at, released_by, corrected_at
           FROM ${this.n.reservations} WHERE state IN ('expired_spent', 'expired') ORDER BY settled_at, id LIMIT $1::integer`,
        [limit],
      ),
    );
    return rows.map(reservationInfo);
  }
}

function reservationInfo(r: Record<string, unknown>): ReservationInfo {
  return {
    id: String(r.id),
    state: r.state as ReservationState,
    keys: r.mandate_keys as string[],
    currency: String(r.currency),
    amount: toSafeInteger(r.amount, 'amount'),
    createdAt: toDate(r.created_at),
    expiresAt: toDate(r.expires_at),
    ...(r.settled_at !== null && r.settled_at !== undefined ? { settledAt: toDate(r.settled_at) } : {}),
    ...(r.released_by === 'release' || r.released_by === 'reconcile' ? { releasedBy: r.released_by } : {}),
    ...(r.corrected_at !== null && r.corrected_at !== undefined ? { correctedAt: toDate(r.corrected_at) } : {}),
  };
}

export interface PostgresNonceOptions extends PostgresNamingOptions {
  /**
   * Separates uses of the same table: invocation nonces and OpenID4VP sessions must never share one.
   * Default `invocation`.
   */
  namespace?: string;
  /**
   * How long a consumed nonce is remembered, in seconds. Must be at least the verifier's
   * maxInvocationAgeSeconds + skewSeconds; see `nonceRetentionSeconds`. Default 600.
   */
  retentionSeconds?: number;
}

/** Single-use nonces shared by every instance: the first `consume` wins, across processes. */
export class PostgresNonceStore implements NonceStore {
  private readonly n: Names;
  private readonly ns: string;
  /** How long a consumed nonce is remembered, so a verifier can check it covers its acceptance window. */
  readonly retentionSeconds: number;

  constructor(
    private readonly db: SqlClient,
    opts: PostgresNonceOptions = {},
  ) {
    this.n = names(opts);
    this.ns = opts.namespace ?? 'invocation';
    if (typeof this.ns !== 'string' || !/^[A-Za-z0-9_.:-]{1,64}$/.test(this.ns)) throw new RangeError('namespace must match /^[A-Za-z0-9_.:-]{1,64}$/');
    this.retentionSeconds = durationSeconds('retentionSeconds', opts.retentionSeconds, 600);
  }

  /**
   * Inserts the nonce, or takes over a row whose retention has passed. Under concurrency exactly one
   * caller gets a row back: the others wait on the unique index and then see it taken.
   */
  async consume(nonce: string): Promise<boolean> {
    const digest = nonceDigest(nonce);
    if (!digest) return false;
    const t = this.n.nonces;
    const rows = rowsOf(
      await this.db.query(
        `INSERT INTO ${t} AS t (namespace, nonce_hash, expires_at)
         VALUES ($1, $2, now() + make_interval(secs => $3::double precision))
         ON CONFLICT (namespace, nonce_hash) DO UPDATE SET expires_at = EXCLUDED.expires_at
           WHERE t.expires_at <= now()
         RETURNING 1 AS ok`,
        [this.ns, digest, this.retentionSeconds],
      ),
    );
    return rows.length === 1;
  }

  /** Deletes nonces past their retention, in every namespace. Returns how many were deleted. */
  async sweep(opts: { limit?: number } = {}): Promise<number> {
    const limit = positiveInt('limit', opts.limit, 10_000);
    const t = this.n.nonces;
    const rows = rowsOf(
      await this.db.query(
        `WITH gone AS (
           DELETE FROM ${t} WHERE ctid IN (SELECT ctid FROM ${t} WHERE expires_at <= now() LIMIT $1::integer)
           RETURNING 1)
         SELECT count(*) AS n FROM gone`,
        [limit],
      ),
    );
    return toSafeInteger(rows[0]?.n ?? 0, 'count');
  }
}

/**
 * The `sessions` store for `handleMandateResponse`: a nonce store in its own namespace, remembering each
 * answered request for as long as a request can be answered (`maxAgeSeconds`, default 600) plus a margin.
 */
export function createPostgresResponseSessionStore(
  db: SqlClient,
  opts: PostgresNamingOptions & { maxAgeSeconds?: number; namespace?: string } = {},
): PostgresNonceStore {
  return new PostgresNonceStore(db, {
    ...opts,
    namespace: opts.namespace ?? 'openid4vp-response',
    retentionSeconds: (opts.maxAgeSeconds ?? 600) + 60,
  });
}

/** Revocations that survive restarts and are seen by every instance at once. */
export class PostgresRevocationRegistry implements ManagedRevocationRegistry {
  private readonly n: Names;
  constructor(
    private readonly db: SqlClient,
    opts: PostgresNamingOptions = {},
  ) {
    this.n = names(opts);
  }

  async revoke(mandateId: string, reason?: string): Promise<void> {
    validateMandateId(mandateId);
    if (reason !== undefined && (typeof reason !== 'string' || reason.length > 1024)) throw new RangeError('reason must be a string of at most 1024 characters');
    await this.db.query(`INSERT INTO ${this.n.revocations} (mandate_id, reason) VALUES ($1, $2) ON CONFLICT (mandate_id) DO NOTHING`, [
      mandateId,
      reason ?? null,
    ]);
  }

  async unrevoke(mandateId: string): Promise<void> {
    validateMandateId(mandateId);
    await this.db.query(`DELETE FROM ${this.n.revocations} WHERE mandate_id = $1`, [mandateId]);
  }

  /** Throws on an id no mandate could have, so the verifier denies rather than skipping the check. */
  async isRevoked(mandateId: string): Promise<boolean> {
    validateMandateId(mandateId);
    const rows = rowsOf(await this.db.query(`SELECT 1 AS hit FROM ${this.n.revocations} WHERE mandate_id = $1`, [mandateId]));
    return rows.length > 0;
  }
}

/** Request sessions shared between instances; see {@link MandateSessionStore}. */
export class PostgresMandateSessionStore implements MandateSessionStore {
  private readonly n: Names;
  /** Default lifetime of a stored request session, in seconds. */
  readonly retentionSeconds: number;
  constructor(
    private readonly db: SqlClient,
    opts: PostgresNamingOptions & { ttlSeconds?: number } = {},
  ) {
    this.n = names(opts);
    this.retentionSeconds = durationSeconds('ttlSeconds', opts.ttlSeconds, 600);
  }

  async put(id: string, session: MandateRequestSession, ttlSeconds?: number): Promise<void> {
    validateSessionId(id);
    const ttl = durationSeconds('ttlSeconds', ttlSeconds, this.retentionSeconds);
    const data = await serializeSession(session);
    const t = this.n.sessions;
    const rows = rowsOf(
      await this.db.query(
        `INSERT INTO ${t} AS t (id, data, expires_at) VALUES ($1, $2, now() + make_interval(secs => $3::double precision))
         ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, expires_at = EXCLUDED.expires_at WHERE t.expires_at <= now()
         RETURNING 1 AS ok`,
        [id, data, ttl],
      ),
    );
    // Never overwrite a live session: another request with the same id would hijack its key.
    if (rows.length !== 1) throw new Error('a live session with this id already exists');
  }

  async get(id: string): Promise<MandateRequestSession | undefined> {
    validateSessionId(id);
    const rows = rowsOf(await this.db.query(`SELECT data FROM ${this.n.sessions} WHERE id = $1 AND expires_at > now()`, [id]));
    return rows.length ? deserializeSession(String(rows[0].data)) : undefined;
  }

  async delete(id: string): Promise<void> {
    validateSessionId(id);
    await this.db.query(`DELETE FROM ${this.n.sessions} WHERE id = $1`, [id]);
  }

  async sweep(opts: { limit?: number } = {}): Promise<number> {
    const limit = positiveInt('limit', opts.limit, 10_000);
    const t = this.n.sessions;
    const rows = rowsOf(
      await this.db.query(
        `WITH gone AS (DELETE FROM ${t} WHERE id IN (SELECT id FROM ${t} WHERE expires_at <= now() LIMIT $1::integer) RETURNING 1)
         SELECT count(*) AS n FROM gone`,
        [limit],
      ),
    );
    return toSafeInteger(rows[0]?.n ?? 0, 'count');
  }
}

/**
 * Idempotency keys shared by every instance. `claim` is one INSERT ... ON CONFLICT: under concurrency exactly
 * one caller takes a free key, the others wait on the row and then see it held.
 */
export class PostgresIdempotencyStore implements IdempotencyStore {
  private readonly n: Names;
  readonly retentionSeconds: number;
  readonly leaseSeconds: number;

  constructor(
    private readonly db: SqlClient,
    opts: IdempotencyStoreOptions & PostgresNamingOptions = {},
  ) {
    this.n = names(opts);
    this.retentionSeconds = idempotencyDuration('retentionSeconds', opts.retentionSeconds, 24 * 3600);
    this.leaseSeconds = idempotencyDuration('leaseSeconds', opts.leaseSeconds, 300);
  }

  /** Columns of a live record, with an abandoned attempt shown as unknown. Free and expired rows are not live. */
  private select(where: string): string {
    return `SELECT key, fingerprint, attempt::text AS attempt, reservation, result,
              CASE WHEN state = 'in_progress' AND lease_until <= now() THEN 'unknown' ELSE state END AS state
              FROM ${this.n.idempotency}
             WHERE ${where} AND state <> 'free' AND NOT (state = 'executed' AND expires_at <= now())`;
  }

  private record(row: Record<string, unknown>): IdempotencyRecord {
    const state = String(row.state) as IdempotencyState;
    if (state !== 'in_progress' && state !== 'unknown' && state !== 'executed') throw new TypeError('invalid idempotency state from the database');
    return {
      key: String(row.key),
      fingerprint: String(row.fingerprint),
      state,
      attempt: String(row.attempt),
      ...(row.reservation !== null && row.reservation !== undefined ? { reservation: String(row.reservation) } : {}),
      ...(row.result !== null && row.result !== undefined ? { result: String(row.result) } : {}),
    };
  }

  async claim(key: string, fingerprint: string): Promise<IdempotencyClaim> {
    validateIdempotencyKey(key);
    validateFingerprint(fingerprint);
    const t = this.n.idempotency;
    // A row seen as free (or expired) by the first statement can be taken by another instance before the
    // second: try again a few times, then report the key as held by whoever took it.
    for (let i = 0; i < 3; i++) {
      const attempt = randomUUID();
      const taken = rowsOf(
        await this.db.query(
          `INSERT INTO ${t} AS t (key, fingerprint, state, attempt, lease_until)
           VALUES ($1, $2, 'in_progress', $3::uuid, now() + make_interval(secs => $4::double precision))
           ON CONFLICT (key) DO UPDATE
              SET fingerprint = EXCLUDED.fingerprint, state = 'in_progress', attempt = EXCLUDED.attempt,
                  reservation = NULL, result = NULL, created_at = now(), lease_until = EXCLUDED.lease_until, expires_at = NULL
            WHERE t.state = 'free' OR (t.state = 'executed' AND t.expires_at <= now())
           RETURNING attempt::text AS attempt`,
          [key, fingerprint, attempt, this.leaseSeconds],
        ),
      );
      if (taken.length === 1 && String(taken[0].attempt) === attempt) return { claimed: true, attempt };
      const held = rowsOf(await this.db.query(this.select('key = $1'), [key]));
      if (held.length === 1) return { claimed: false, record: this.record(held[0]) };
    }
    throw new Error('the idempotency key could not be claimed or read');
  }

  async attach(key: string, attempt: string, reservation: string): Promise<void> {
    validateIdempotencyKey(key);
    if (!isAttemptId(attempt) || typeof reservation !== 'string' || reservation.length === 0 || reservation.length > 256) return;
    await this.db.query(
      `UPDATE ${this.n.idempotency} SET reservation = $3 WHERE key = $1 AND attempt = $2::uuid AND state IN ('in_progress', 'unknown')`,
      [key, attempt, reservation],
    );
  }

  async finish(key: string, attempt: string, outcome: AttemptOutcome, result?: string): Promise<void> {
    validateIdempotencyKey(key);
    validateOutcome(outcome);
    validateResult(result);
    if (!isAttemptId(attempt)) return;
    const t = this.n.idempotency;
    if (outcome === 'executed') {
      // Also from free: proof that the action ran wins over an earlier "did not run".
      await this.db.query(
        `UPDATE ${t} SET state = 'executed', result = $3, lease_until = NULL,
                expires_at = now() + make_interval(secs => $4::double precision)
          WHERE key = $1 AND attempt = $2::uuid AND state IN ('in_progress', 'unknown', 'free')`,
        [key, attempt, result ?? null, this.retentionSeconds],
      );
    } else if (outcome === 'not_executed') {
      await this.db.query(
        `UPDATE ${t} SET state = 'free', result = NULL, lease_until = NULL,
                expires_at = now() + make_interval(secs => $3::double precision)
          WHERE key = $1 AND attempt = $2::uuid AND state IN ('in_progress', 'unknown')`,
        [key, attempt, this.retentionSeconds],
      );
    } else {
      await this.db.query(`UPDATE ${t} SET state = 'unknown' WHERE key = $1 AND attempt = $2::uuid AND state = 'in_progress'`, [key, attempt]);
    }
  }

  async resolve(key: string, outcome: 'executed' | 'not_executed', attempt: string): Promise<boolean> {
    validateIdempotencyKey(key);
    if (outcome !== 'executed' && outcome !== 'not_executed') throw new RangeError('outcome must be executed or not_executed');
    if (!isAttemptId(attempt)) throw new RangeError('resolve needs the attempt that holds the key');
    const rows = rowsOf(
      await this.db.query(
        `UPDATE ${this.n.idempotency} SET state = $2, lease_until = NULL,
                expires_at = now() + make_interval(secs => $3::double precision)
          WHERE key = $1 AND attempt = $4::uuid AND state IN ('in_progress', 'unknown')
         RETURNING 1 AS ok`,
        [key, outcome === 'executed' ? 'executed' : 'free', this.retentionSeconds, attempt],
      ),
    );
    return rows.length === 1;
  }

  async get(key: string): Promise<IdempotencyRecord | undefined> {
    validateIdempotencyKey(key);
    const rows = rowsOf(await this.db.query(this.select('key = $1'), [key]));
    return rows.length === 1 ? this.record(rows[0]) : undefined;
  }

  async unresolved(opts: { limit?: number } = {}): Promise<IdempotencyRecord[]> {
    const limit = positiveInt('limit', opts.limit, 100, 10_000);
    const rows = rowsOf(
      await this.db.query(
        `${this.select(`(state = 'unknown' OR (state = 'in_progress' AND lease_until <= now()))`)} ORDER BY created_at LIMIT $1::integer`,
        [limit],
      ),
    );
    return rows.map((r) => this.record(r));
  }

  /** Deletes executed and free records past their retention. Returns how many were deleted. */
  async sweep(opts: { limit?: number } = {}): Promise<number> {
    const limit = positiveInt('limit', opts.limit, 10_000);
    const t = this.n.idempotency;
    const rows = rowsOf(
      await this.db.query(
        `WITH gone AS (
           DELETE FROM ${t} WHERE ctid IN (
             SELECT ctid FROM ${t} WHERE state IN ('executed', 'free') AND expires_at <= now() LIMIT $1::integer)
           RETURNING 1)
         SELECT count(*) AS n FROM gone`,
        [limit],
      ),
    );
    return toSafeInteger(rows[0]?.n ?? 0, 'count');
  }
}
