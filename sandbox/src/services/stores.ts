/**
 * Where the bank keeps spending reservations and consumed nonces, and the platform its OpenID4VP sessions.
 *
 * - `memory` (default): one process, nothing to install.
 * - `postgres` (PLENIPO_PG_URL): the library's Postgres stores, shared by every instance on the database.
 * - `redis` (PLENIPO_REDIS_URL): the library's Redis stores.
 *
 * The drivers (`pg`, `ioredis`) are optional dependencies of the sandbox, loaded only when asked for.
 * Shared ledgers turn reservations left pending past their TTL (a crash, or a tool that threw: the
 * outcome is unknown) into `expired_spent`; the bank runs that sweep periodically and the dashboard
 * lists them until someone reconciles them.
 */
import {
  createPostgresResponseSessionStore,
  createRedisResponseSessionStore,
  fromIoredis,
  InMemoryNonceStore,
  InMemorySpendingLedger,
  migratePostgres,
  nonceRetentionSeconds,
  PostgresMandateSessionStore,
  PostgresNonceStore,
  PostgresSpendingLedger,
  RedisMandateSessionStore,
  RedisNonceStore,
  RedisSpendingLedger,
  type NonceStore,
  type ReconcileOutcome,
  type ReservationInfo,
  type ReservationState,
  type SpendingLedger,
} from 'plenipo';
import { InMemoryMandateSessionStore, type PlatformStores } from './platform.js';

export type StoreKind = 'memory' | 'postgres' | 'redis';

/** A shared ledger: reservations can expire, be listed and be reconciled. */
interface SweepableLedger extends SpendingLedger {
  sweepExpired(opts?: { limit?: number }): Promise<number>;
  unresolved(opts?: { limit?: number }): Promise<ReservationInfo[]>;
  reconcile(id: string, outcome: ReconcileOutcome): Promise<ReservationState | 'unknown'>;
}

export interface BankStores {
  kind: StoreKind;
  ledger: SpendingLedger;
  nonces: NonceStore;
  /** Present for shared stores: the sweep, the unresolved list and reconciliation. */
  reservations?: {
    sweep(): Promise<number>;
    unresolved(): Promise<ReservationInfo[]>;
    reconcile(id: string, outcome: ReconcileOutcome): Promise<ReservationState | 'unknown'>;
  };
}

export interface SandboxStores {
  kind: StoreKind;
  bank: BankStores;
  platform: PlatformStores;
  /** Sweeps expired nonces and sessions (the ledger sweep is the bank's). */
  housekeeping(): Promise<void>;
  close(): Promise<void>;
}

export interface StoreOptions {
  kind?: StoreKind;
  /** Connection string for postgres or redis. */
  url?: string;
  /** Table prefix (postgres) or key prefix (redis), so several sandboxes can share a server. */
  prefix?: string;
  /** How long a reservation may stay pending before the sweep counts it as spent. Default 900; the sandbox demo uses less. */
  pendingTtlSeconds?: number;
}

/** Reads the store choice from the environment: SANDBOX_STORES, PLENIPO_PG_URL, PLENIPO_REDIS_URL. */
export function storeOptionsFromEnv(env = process.env): StoreOptions {
  const kind = (env.SANDBOX_STORES as StoreKind | undefined) ?? (env.PLENIPO_PG_URL ? 'postgres' : env.PLENIPO_REDIS_URL ? 'redis' : 'memory');
  const url = kind === 'postgres' ? env.PLENIPO_PG_URL : kind === 'redis' ? env.PLENIPO_REDIS_URL : undefined;
  return {
    kind,
    url,
    prefix: env.PLENIPO_STORE_PREFIX,
    pendingTtlSeconds: env.SANDBOX_PENDING_TTL_SECONDS ? Number(env.SANDBOX_PENDING_TTL_SECONDS) : undefined,
  };
}

// Invocations are accepted up to 120 s old with 60 s of skew: nonces must be remembered at least that long.
const NONCE_RETENTION = nonceRetentionSeconds({ maxInvocationAgeSeconds: 120, skewSeconds: 60 });

async function optionalImport<T>(name: string): Promise<T> {
  try {
    return (await import(name)) as T;
  } catch {
    throw new Error(`the ${name} package is not installed: run npm install ${name} in sandbox/ (it is an optional dependency)`);
  }
}

function reservationsOf(ledger: SweepableLedger): BankStores['reservations'] {
  return {
    async sweep() {
      let total = 0;
      // The sweep handles at most `limit` per call; call again while it returns a full batch.
      for (let n = await ledger.sweepExpired({ limit: 500 }); ; n = await ledger.sweepExpired({ limit: 500 })) {
        total += n;
        if (n < 500) break;
      }
      return total;
    },
    unresolved: () => ledger.unresolved({ limit: 100 }),
    reconcile: (id, outcome) => ledger.reconcile(id, outcome),
  };
}

export async function createStores(opts: StoreOptions = {}): Promise<SandboxStores> {
  const kind = opts.kind ?? 'memory';
  switch (kind) {
    case 'memory':
      return {
        kind,
        bank: { kind, ledger: new InMemorySpendingLedger(), nonces: new InMemoryNonceStore() },
        platform: { requestSessions: new InMemoryMandateSessionStore(), responseSessions: new InMemoryNonceStore() },
        housekeeping: async () => {},
        close: async () => {},
      };
    case 'postgres': {
      if (!opts.url) throw new Error('set PLENIPO_PG_URL to use the Postgres stores');
      const pg = await optionalImport<{ default: { Pool: new (o: Record<string, unknown>) => { query: (...a: never[]) => Promise<{ rows: unknown[] }>; end(): Promise<void> } } }>('pg');
      const pool = new pg.default.Pool({ connectionString: opts.url, max: 10, statement_timeout: 5000 });
      const naming = { tablePrefix: opts.prefix ?? 'plenipo_' };
      try {
        await migratePostgres(pool, naming);
      } catch (e) {
        await pool.end().catch(() => {});
        throw new Error(`could not prepare the Postgres schema at ${redact(opts.url)}: ${(e as Error).message}`);
      }
      const ledger = new PostgresSpendingLedger(pool, { ...naming, pendingTtlSeconds: opts.pendingTtlSeconds });
      const nonces = new PostgresNonceStore(pool, { ...naming, retentionSeconds: NONCE_RETENTION });
      const requestSessions = new PostgresMandateSessionStore(pool, naming);
      const responseSessions = createPostgresResponseSessionStore(pool, naming);
      return {
        kind,
        bank: { kind, ledger, nonces, reservations: reservationsOf(ledger) },
        platform: { requestSessions, responseSessions },
        housekeeping: async () => {
          await nonces.sweep();
          await responseSessions.sweep();
          await requestSessions.sweep();
        },
        close: () => pool.end(),
      };
    }
    case 'redis': {
      if (!opts.url) throw new Error('set PLENIPO_REDIS_URL to use the Redis stores');
      const mod = await optionalImport<{ default: new (url: string, o: Record<string, unknown>) => Parameters<typeof fromIoredis>[0] & { connect(): Promise<void>; quit(): Promise<unknown> } }>('ioredis');
      const client = new mod.default(opts.url, { lazyConnect: true, maxRetriesPerRequest: 2, connectTimeout: 5000 });
      try {
        await client.connect();
      } catch (e) {
        throw new Error(`could not connect to Redis at ${redact(opts.url)}: ${(e as Error).message}`);
      }
      const redis = fromIoredis(client);
      const prefix = opts.prefix ?? 'plenipo';
      const ledger = new RedisSpendingLedger(redis, { prefix, pendingTtlSeconds: opts.pendingTtlSeconds });
      return {
        kind,
        bank: { kind, ledger, nonces: new RedisNonceStore(redis, { prefix, retentionSeconds: NONCE_RETENTION }), reservations: reservationsOf(ledger) },
        platform: { requestSessions: new RedisMandateSessionStore(redis, { prefix }), responseSessions: createRedisResponseSessionStore(redis, { prefix }) },
        // Redis expires nonces and sessions by itself.
        housekeeping: async () => {},
        close: async () => {
          await client.quit().catch(() => {});
        },
      };
    }
    default:
      throw new Error(`unknown store kind ${String(kind)} (memory, postgres or redis)`);
  }
}

/** A connection string without its password, for error messages. */
function redact(url: string): string {
  try {
    const u = new URL(url);
    if (u.password) u.password = '***';
    return u.toString();
  } catch {
    return '(invalid URL)';
  }
}
