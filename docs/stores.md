# Shared stores: Postgres and Redis

`verifyAuthorization` and `handleMandateResponse` keep state in five places: the
spending ledger, the invocation nonce store, the idempotency store, the OpenID4VP
response session store and the revocation registry. The in-memory implementations are correct
only inside one Node.js process. As soon as a relying party runs more than one
verifier (several API gateway replicas, several workers), those stores must be
shared, or each replica enforces its own copy of every limit and accepts every
replay once.

This module provides shared implementations on Postgres and on Redis. They take
no runtime dependency: each store receives a small client interface that the
common drivers satisfy directly or through a three-line adapter.

| Interface | Postgres | Redis |
| --- | --- | --- |
| `SpendingLedger` | `PostgresSpendingLedger` | `RedisSpendingLedger` |
| `NonceStore` (invocations) | `PostgresNonceStore` | `RedisNonceStore` |
| `IdempotencyStore` | `PostgresIdempotencyStore` | `RedisIdempotencyStore` |
| `NonceStore` (`sessions` of `handleMandateResponse`) | `createPostgresResponseSessionStore` | `createRedisResponseSessionStore` |
| `RevocationRegistry` (+ `revoke`, `unrevoke`) | `PostgresRevocationRegistry` | `RedisRevocationRegistry` |
| `MandateSessionStore` (request sessions between instances) | `PostgresMandateSessionStore` | `RedisMandateSessionStore` |

## Which engine

Use **Postgres for the ledger and for revocations**. Both protect money: a
forgotten reservation lets an agent overspend, a forgotten revocation lets a
revoked agent act. Postgres commits are durable and a synchronous standby can
make them survive a failover.

Redis is fine for nonces and sessions when its durability matches your risk,
and it can hold the ledger too, but read "Redis durability" below first: with
the default configuration a restart or a failover forgets recent writes.

## Setup

### Postgres

```ts
import pg from 'pg';
import {
  migratePostgres, PostgresSpendingLedger, PostgresNonceStore, PostgresRevocationRegistry,
  createPostgresResponseSessionStore, nonceRetentionSeconds,
} from 'plenipo';

const pool = new pg.Pool({ connectionString: process.env.DATABASE_URL, statement_timeout: 5000 });
await migratePostgres(pool); // idempotent; every replica may call it at start-up

const verifyOpts = {
  audience: 'https://bank.example',
  trustAnchors,
  ledger: new PostgresSpendingLedger(pool, { pendingTtlSeconds: 900 }),
  nonces: new PostgresNonceStore(pool, { retentionSeconds: nonceRetentionSeconds({ maxInvocationAgeSeconds: 120, skewSeconds: 60 }) }),
  revocation: new PostgresRevocationRegistry(pool),
};
const responseOpts = { now: nowSeconds(), trustAnchors, sessions: createPostgresResponseSessionStore(pool) };
```

`SqlClient` is `{ query(text, params?): Promise<{ rows: unknown[] }> }`. A `pg`
`Pool`, a `pg` `Client` and a PGlite instance fit as they are (the tests pass
each of them where a `SqlClient` is expected). Every store operation is a
single statement, so a pool may run it on any connection and a crashed caller
never leaves a transaction open.

Naming: `tablePrefix` (default `plenipo_`) prefixes every table, index and
function; `schema` qualifies them all. Both are validated against
`/^[a-z_][a-z0-9_]*$/` before being interpolated into SQL.

The schema ships three ways: `migratePostgres(client, opts)`, the string
`postgresSchema(opts)` (and `POSTGRES_SCHEMA_SQL` with default names) for your
migration tool, and the file `src/stores/schema.sql`, which a test keeps
identical to `POSTGRES_SCHEMA_SQL`. `migratePostgres` runs the whole schema as
one `DO` block under a transaction-scoped advisory lock, so replicas migrating
at the same moment wait for each other. The `schema_meta` table records the
schema version (currently 4). Upgrading from versions 1 to 3 is part of the
same migration (the `schema_upgrade` function runs each step once: version 2
widens the reservation state constraint, version 3 adds the `released_by` and
`corrected_at` columns, version 4 adds the `idempotency` table); existing rows
keep their meaning.

Tables: `ledger` (committed and pending spending per mandate key and currency,
BIGINT minor units), `reservations`, `nonces`, `revocations`,
`request_sessions`, `schema_meta`. Functions: `ledger_reserve`,
`ledger_settle`, `ledger_expire`. The functions are `SECURITY INVOKER`: the
application role needs `SELECT, INSERT, UPDATE, DELETE` on the tables and
`EXECUTE` on the functions; only the migration role needs DDL rights.

### Redis

```ts
import { Redis } from 'ioredis';                // or: import { createClient } from 'redis'
import { fromIoredis, RedisNonceStore } from 'plenipo';

const redis = fromIoredis(new Redis(process.env.REDIS_URL));
// node-redis v4 or later:
//   const client = createClient({ url: process.env.REDIS_URL }); await client.connect();
//   const redis = fromNodeRedis(client);
const nonces = new RedisNonceStore(redis, { retentionSeconds: 240 });
```

`RedisClient` has three methods: `eval(script, keys, args)`,
`evalsha(sha1, keys, args)` and `setNxPx(key, value, ms)`. The adapters map
them onto each driver's real signatures:

| | ioredis (`Redis`, `Cluster`) | node-redis v4+ (`createClient`, `createCluster`) |
| --- | --- | --- |
| eval | `eval(script, numkeys, ...keys, ...args)` | `eval(script, { keys, arguments })` |
| evalsha | `evalsha(sha, numkeys, ...keys, ...args)` | `evalSha(sha, { keys, arguments })` |
| SET NX PX | `set(key, value, 'PX', ms, 'NX')` | `set(key, value, { PX: ms, NX: true })` |

Scripts run with EVALSHA and fall back to EVAL on `NOSCRIPT` (a restarted node,
a failover, a cluster node that has not seen the script yet). For another
driver, implement `RedisClient` directly; it is three functions.

## The spending ledger

### Semantics

A reservation moves through these states:

```
reserve ──► pending ──commit──────────────► committed ◄──────────────────────┐
               │  ├──release──────────────► released ──commit / reconcile(executed)
               │  └──reconcile(not_executed) ► released     (correction: counted again)
               └──sweep (TTL)─► expired_spent ──commit / reconcile(executed)──► committed
                                     └──reconcile(not_executed)──► released
```

| Call | pending | expired_spent | released | committed | unknown id |
| --- | --- | --- | --- | --- | --- |
| `commit`, `reconcile(id, 'executed')` | → committed | → committed, not counted twice | → committed, **amount counted again** | no-op | no-op |
| `release` | → released, amount given back | **no-op** | no-op | no-op | no-op |
| `reconcile(id, 'not_executed')` | → released, amount given back | → released, amount given back | no-op | **no-op** | no-op |
| `sweepExpired` (after the TTL) | → expired_spent, amount stays counted | | | | |

The two kinds of error are not symmetric. Counting an amount that did not move
only makes an agent run out of budget early, and a reconciliation can correct
it. Not counting an amount that did move lets spending exceed the total. So
evidence that the action ran always wins: a commit or `reconcile(id,
'executed')` on a `released` reservation (the API answered 4xx after acting and
the gateway released, or a reconciliation that looked too early gave it back)
counts the amount again. That can put spending over a total; it is the truth,
and the ledger records it rather than hiding a payment that happened. The next
reservation on that mandate is then refused. `reservation(id)` shows such
corrections: `releasedBy` says who released (`'release'` or `'reconcile'`; it
is kept after a correction, and absent for releases recorded before schema
version 3) and `correctedAt` when the release was corrected. Concurrent
commits, releases and reconciliations of one reservation still apply each
transition once; whatever their order, a commit ends in `committed`, counted
once.

`settle` and `reconcile` return the state after the call (`'unknown'` when there
is no such reservation), so a reconciliation job can tell a no-op from a change.
Rows written by schema version 1 may be in the legacy state `expired`: its sweep
gave the amount back without knowing whether the action ran. They are on the
reconciliation list (`unresolved()`), are never purged, and resolve like
`expired_spent`: `reconcile(id, 'executed')` or a commit counts the amount,
`reconcile(id, 'not_executed')` marks them released.

Every transition happens at most once, whatever the number of replicas calling
it concurrently. Ids that are not UUIDs are no-ops without a query.

`reserve(entries, amount)` is all or nothing over the whole chain: either every
entry with a `total` has room for `committed + pending + amount`, and the amount
is added as pending to every entry, or nothing changes and it returns `null`.
Entries without a total are tracked but never block. A key that appears twice
counts once, against the tighter of its totals.

`spent(key, currency)` is committed plus pending, as for the in-memory ledger.

Inputs are validated before any query, because they come from network
messages: the amount must be a non-negative safe integer in minor units, the
currency three upper-case letters, keys strings of 1 to 256 characters, totals
non-negative safe integers, at most 32 entries. Violations throw (the verifier
turns a throw into DENY). The schema repeats the essentials as `CHECK`
constraints (`amount >= 0`, `pending >= 0`, `committed >= 0`), so even a buggy
caller cannot drive a balance negative.

### Postgres: how reserve stays atomic

`ledger_reserve` runs as one statement, which Postgres executes as one
transaction:

1. it creates the missing `(key, currency)` rows, in key order;
2. it locks every row of the chain with `SELECT … ORDER BY mandate_key FOR UPDATE`.
   `LockRows` runs above the sort, so the locks are taken in key order;
3. it checks every total against the locked values; on the first one without
   room it returns false (the transaction holds no change other than empty rows);
4. it adds the amount to `pending` on every row and inserts the reservation.

Taking every lock in the same order (byte order: the key column is
`COLLATE "C"`, so the database locale cannot change it) means two reservations
on overlapping chains queue behind each other and never deadlock. Settle locks
the reservation row first and then its ledger rows in the same key order. The
sweep selects stale reservations with `FOR UPDATE SKIP LOCKED` and updates the
ledger once per key, in key order, after aggregating, so it never holds ledger
locks in an order a reservation could invert.

Run the stores at the default `READ COMMITTED` isolation: each statement inside
the functions then sees the latest committed rows after acquiring the lock.
Under `REPEATABLE READ` or `SERIALIZABLE` the lock may fail with a
serialization error instead of waiting; that fails closed (DENY) but needs
retries to be usable.

Set `statement_timeout` (and possibly `lock_timeout`) on the pool so a stuck
connection turns into a DENY instead of a hung request.

### Redis: how reserve stays atomic

One Lua script reads committed and pending for every entry, compares with the
totals, and only then increments pending on all of them and writes the
reservation hash. Redis runs a script without interleaving other commands, so
the check and the increments are atomic across all clients. Commit, release and
expiry are scripts too.

Keys of one ledger:

```
{<prefix>:ledger}:committed      hash  "<CUR>:<mandate key>" -> minor units
{<prefix>:ledger}:pending        hash  "<CUR>:<mandate key>" -> minor units
{<prefix>:ledger}:res:<uuid>     hash  state, currency, amount, keys, created, expires, settled
{<prefix>:ledger}:expiry         zset  pending reservation ids scored by expiry time (ms)
{<prefix>:ledger}:unresolved     zset  expired_spent reservation ids scored by expiry time (ms)
```

**Redis Cluster.** A script may only touch keys of one hash slot. Every key of a
ledger carries the same hash tag `{<prefix>:ledger}`, so the whole ledger lives
in one slot, on one shard. This is required: a chain's mandate keys are
arbitrary hashes and would otherwise land on different shards. It also means a
ledger does not scale horizontally across shards; use separate prefixes (and
therefore separate slots) for independent ledgers, e.g. per tenant. Prefixes may
not contain braces, so a stray hash tag cannot split a ledger.

Times come from the Redis server (`TIME`), not from each replica's clock.

Pending and `expired_spent` reservation hashes have **no TTL**: a pending one
must be seen by the sweep, and an `expired_spent` one must stay available to
the reconciliation. The TTL (`settledRetentionSeconds`, default 7 days) is set
when the reservation is committed or released; it bounds how long a repeated
commit or release stays a no-op.

### Stale reservations, the sweep and reconciliation

`verifyAuthorization` reserves; the relying party commits after performing the
action, or releases when the action certainly did not run. Between ALLOW and
that call anything can happen: the process crashes or is killed by a deploy,
the downstream call times out, the client hangs up, the commit itself fails on
a database error. In every one of these cases **nobody knows whether the money
moved**, and the reservation stays pending.

Limits must fail safe. Giving such an amount back would let an agent exceed its
total whenever the payment did go through; keeping it counted can only make the
agent run out of budget early. So each reservation gets an expiry
(`pendingTtlSeconds`, default 900), and `sweepExpired({ limit })` turns pending
reservations past it into `expired_spent`: the amount moves from pending to
committed and stays in the totals. A stuck reservation therefore reduces the
available budget but never lets spending exceed it. Schedule the sweep on one or
more instances, every minute or so; concurrent sweeps are safe and each
reservation is expired once. It returns how many it expired; call again while it
returns `limit`. The sweep keeps the `pending` column honest (it then only holds
reservations still in flight) and puts stuck reservations on a work list.

Only an explicit reconciliation gives an amount back. Run a reconciliation job
(or give operators a console) that takes `unresolved({ limit })`, the
`expired_spent` (and legacy `expired`) reservations oldest first, matches each
one against the payment rail or the downstream system's records, and calls:

- `reconcile(id, 'not_executed')` when it has established that the action did
  not happen: the amount is given back (this also works on a reservation still
  pending, for a job that can decide before the TTL);
- `reconcile(id, 'executed')` when the action happened: the reservation becomes
  committed without being counted twice (a late `commit` from the original
  caller does the same). It also works on a `released` reservation, so the job
  can correct releases too, for example by matching the rail's payments against
  reservations the gateway released after a 4xx.

`release` never touches an `expired_spent` reservation, and nothing gives back a
committed one. Choose the TTL longer than the slowest action between ALLOW and
commit, including retries of the payment rail, so that the sweep only catches
reservations whose caller is really gone.

`PostgresSpendingLedger.purgeSettled({ olderThanSeconds })` deletes committed
and released reservations settled before the given age; keep them as long as an
audit, a duplicate commit or a correction of a release may need them (after the
purge a late commit of a released reservation is a no-op). `expired_spent` and
legacy `expired` reservations are never purged: they wait for reconciliation.
On Redis, committed and released reservations expire after
`settledRetentionSeconds` with the same consequence.

Redis ledgers written before reconciliation existed may hold legacy `expired`
reservation hashes with a TTL. `RedisSpendingLedger.adoptLegacyExpired()` scans
the ledger's keys once, removes their TTL and puts them on the `unresolved`
list; run it once after upgrading. It is idempotent.
`reservation(id)` returns what the store knows about one reservation.

## Nonces

`consume(nonce)` returns true exactly once per nonce across all instances, even
when many race for it:

- Postgres: `INSERT … ON CONFLICT (namespace, nonce_hash) DO UPDATE … WHERE
  expires_at <= now() RETURNING 1`. One inserter wins; the others wait on the
  unique index and get no row. A row whose retention has passed can be taken
  over, which matches Redis key expiry.
- Redis: `SET key 1 PX <retention> NX`.

Nonces are stored as SHA-256 hashes: fixed size, and no attacker-chosen bytes in
keys or indexes. A nonce that is not a string of 1 to 512 characters is never
accepted.

**Retention.** The verifier accepts an invocation from `iat - skew` to
`iat + maxInvocationAgeSeconds`, so its nonce must be remembered at least
`maxInvocationAgeSeconds + skewSeconds` after consumption, plus a margin for
clock differences between replicas and the store. `nonceRetentionSeconds(opts)`
computes this (default 120 + 60 + 60 = 240 s); the stores default to 600 s.
A shorter retention re-opens replay. Every nonce store exposes its configured
value as `retentionSeconds` (`InMemoryNonceStore` reports `Infinity`), so the
verifier can refuse a configuration where it is shorter than its acceptance
window.

`namespace` separates uses of the same table or key space. Invocation nonces and
OpenID4VP response sessions must never share a namespace: the OpenID4VP `state`
is visible to anyone who sees the request. `PostgresNonceStore.sweep()` deletes
expired rows (Redis expires keys on its own).

## Idempotency keys

`IdempotencyStore` keeps the keys that let an agent retry a call whose outcome
it did not learn (docs/spec.md, section 5.1). One record per scoped key holds
the request fingerprint, the attempt that holds the key, its reservation, and
the stored result of an executed attempt.

| State | Meaning | Kept |
| --- | --- | --- |
| `in_progress` | an attempt holds the key and is running | until finished; after `leaseSeconds` (default 300) it reads as `unknown` |
| `unknown` | the attempt ended without knowing whether it ran, or was abandoned | until resolved: never forgotten |
| `executed` | it ran; `result` is what the service stored for replays | `retentionSeconds` (default one day) |
| `free` (internal) | it certainly did not run; the next `claim` takes the key | `retentionSeconds`, so a late "executed" still lands |

`claim(key, fingerprint)` takes a free key for a new attempt or returns the
record that holds it, atomically across instances:

- Postgres: one `INSERT … ON CONFLICT (key) DO UPDATE … WHERE state = 'free' OR
  (state = 'executed' AND expires_at <= now()) RETURNING attempt`. Concurrent
  claims wait on the row and then see it held.
- Redis: one Lua script per operation, every key of a store under the hash tag
  `{<prefix>:idem}`. Keys are hashed into names. Unresolved attempts sit in a
  sorted set (score: lease end, or 0 once unknown) that `unresolved()` reads.

`finish(key, attempt, outcome, result?)` ends an attempt; only the attempt
that holds the key can end it, and `executed` is final. Proof that the action
ran wins, as in the ledger: an `executed` from an attempt whose key was freed
in the meantime, and not claimed again, still marks the key executed.

**Reconciliation.** `unresolved()` lists the keys blocked on an unknown
outcome; `resolve(key, 'executed' | 'not_executed')` settles one. When the
attempt held a reservation of a Postgres or Redis ledger, reconciling the
reservation is enough: on the next retry the verifier reads the reservation, a
committed one marks the key executed and a released one frees it. Keys of
calls that reserved nothing (no total limit) need `resolve`.

**Retention.** After `retentionSeconds` an executed key is forgotten and a
retry with it runs again: keep it longer than any retry an agent may make.
`PostgresIdempotencyStore.sweep()` deletes expired rows; Redis expires them on
its own. Stored results contain whatever the service returned, personal data
included; `maxReplayBytes` (guard and gateway, default 64 KiB, `0` for none)
bounds them, and a store refuses results above 256 KiB.

## OpenID4VP sessions

`handleMandateResponse` needs a `sessions` nonce store so that each wallet
response is redeemed once; it consumes `openid4vp:<state>` after full
verification, and an error response does not consume it.
`createPostgresResponseSessionStore` and `createRedisResponseSessionStore`
return a nonce store in the `openid4vp-response` namespace with a retention of
`maxAgeSeconds + 60` (default 660 s).

Across instances the request session itself (nonce, state, transaction data
and, for encrypted responses, the ephemeral decryption key) must also be
shared, because the wallet's POST can reach a different instance from the one
that created the request. `MandateSessionStore` does that:

```ts
const req = await createMandateRequest({ mandate, clientId, responseUri: `https://agents.example/vp/${requestId}` });
await requestSessions.put(requestId, req.session);           // instance A
// … wallet POSTs to /vp/:requestId, served by instance B
const session = await requestSessions.get(requestId);
const result = await handleMandateResponse(body, session, { ...rootOpts, sessions: responseSessions });
await requestSessions.delete(requestId);
```

Key the session by an id the wallet sends back in the clear, such as a path
segment of the `response_uri`: with `direct_post.jwt` the `state` is inside the
encrypted response. `put` refuses to overwrite a live session (it would replace
its key); `get` does not consume, so an error response or a failed verification
leaves the session usable until single use is recorded by the `sessions` store.
Sessions expire after `ttlSeconds` (default 600), exposed as
`retentionSeconds`.

The stored session keeps everything `handleMandateResponse` needs, including
the mandate of a TS12 e-mandate request (its transaction data only carries a
hash) and the extra DCQL queries of e-mandate (`sca`) and legal-person
(`representation`) requests. On load the mandate is checked again with
`validateMandate` (and the legal principal with its own validator) and must be
the requested one; `extraQueries` may only list those known query ids, without
repetition. Sessions are serialised in format version 2; version 1 sessions,
written before these members existed, are still read.

The response session store (`createPostgresResponseSessionStore`,
`createRedisResponseSessionStore`) remembers each answered request for
`maxAgeSeconds + 60`; its `retentionSeconds` must be at least the
`maxAgeSeconds` given to `handleMandateResponse`.

The stored session contains the **private** decryption key as a JWK. Anyone who
can read the table or key until the session is deleted or expires can decrypt
that request's response, which carries PID claims. Keep the TTL short, delete
the session after use, and give the store the same protection as other secrets.

## Revocation

`revoke(mandateId, reason?)`, `unrevoke(mandateId)`, `isRevoked(mandateId)`.
Revoking twice keeps the first time. A revocation is visible to every instance
on the next `isRevoked`. `isRevoked` throws for an id that no mandate could
have (empty, or over 1024 characters), so the verifier denies instead of
skipping the check, and any store error also ends in DENY.

Postgres keeps revocations across restarts (the tests restart the server).
Redis keeps them in one hash, `<prefix>:revocations`; they survive a restart
only with persistence enabled.

## Redis durability

Redis acknowledges a write before it is on disk (unless `appendfsync always`)
and before replicas have it (unless the client uses `WAIT`). Consequences:

- after a crash without AOF, every reservation, nonce, revocation and session is
  gone: totals restart from zero, captured invocations can be replayed until
  they age out, revoked mandates work again;
- with `appendfsync everysec`, up to about one second of writes can be lost;
- after a failover to an asynchronous replica, the writes it had not received
  are lost.

For nonces the exposure is limited to invocations younger than
`maxInvocationAgeSeconds`; for the ledger and revocations it is not. If you use
Redis for them, enable AOF with `appendfsync always` or accept and document the
window, and prefer Postgres.

## Security considerations

- Every value from the network is validated before it reaches a query, and all
  values are bound parameters or script arguments; only validated identifiers
  (prefix, schema) are interpolated into SQL.
- Errors fail closed: a store that throws makes `verifyAuthorization` return
  DENY. Store error messages may name tables; the MCP guard never returns the
  `detail` field to callers.
- Spending amounts are BIGINT minor units; JavaScript values are checked to be
  safe integers in both directions, and a database value outside the safe range
  is reported as corruption rather than rounded.
- Nonces, session ids and idempotency keys are hashed before becoming Redis
  keys; prefixes and namespaces are restricted to `[A-Za-z0-9_.:-]`.
- Idempotency keys are scoped by audience and chain hash before they reach a
  store, so agents of different chains cannot collide or block each other's keys.
- The ledger keys are mandate hashes, so delegators cannot choose ids that
  collide with another chain's entries.

## Limits

- `verifyAuthorization` reserves before it consumes the nonce. If the nonce
  store throws (as a network store can), it releases the reservation and denies
  with `INTERNAL`: the action has not run, so giving the amount back is safe.
- A reservation stuck in `expired_spent` stays counted until someone reconciles
  it; without a reconciliation job, an agent whose calls keep failing in an
  unknown state runs out of budget early.
- A Redis ledger lives in one cluster slot per prefix, and so does a Redis
  idempotency store.
- An idempotency key whose attempt is unknown blocks its retries until someone
  resolves it, like an `expired_spent` reservation: without a reconciliation job,
  an agent cannot repeat such a call with the same key.
- The Postgres functions assume `READ COMMITTED`.
- No automatic purge of settled reservations; call `purgeSettled` if you want one.
- The Redis stores are tested against a single redis-server, not a cluster.

## Tests

`test/stores.test.ts` runs the same contract against both engines, through two
independent connections each (two `pg` pools; an ioredis and a node-redis
client), and a PGlite smoke test for driver compatibility. The test setup
(`test/stores-engines.ts`) starts a throwaway Postgres cluster (`initdb` +
`pg_ctl`, as the `postgres` user when running as root) and a `redis-server`
without persistence, each on a random port of 127.0.0.1, and stops them at the
end. When an engine is not available the corresponding tests are skipped with a
message. `PLENIPO_TEST_PG_URL` and `PLENIPO_TEST_REDIS_URL` point the tests at
existing servers; `PLENIPO_PG_BINDIR` and `PLENIPO_REDIS_SERVER` locate the
binaries.

The contract covers: k of 50 parallel reserves succeeding across two
connections; tightest total in the middle of a chain; one full entry blocking
the whole reservation; parallel chains listing the same mandates in opposite
orders (no deadlock); a randomised mix of overlapping chains, commits, releases
and races checked against an independent tally; commit/release idempotency and
races; malformed inputs; the expiry sweep counting stale reservations as spent,
concurrent sweeps and sweeps racing commits; reconciliation (racing replicas,
never on committed); corrections of releases by late commits and
reconciliations, racing from two replicas and beyond a total; the upgrades of
version 1 and version 2 schemas; nonce replay across connections and under a 30-way race; nonce
retention; namespaces; single-use OpenID4VP responses with the request session
created on one instance and the response handled on another; revocation shared
between instances and across a Postgres restart; and `verifyAuthorization` end
to end with the shared ledger and nonce store on two replicas.
`test/stores-regression.test.ts` holds the regression tests of the ops review:
legal-person and TS12 e-mandate requests completed after a session round trip
through Postgres and Redis, tampered stored sessions refused, a payment whose
commit failed staying counted after the sweep, the retention each store
reports, releases corrected by later evidence of execution on both engines, and
the adoption of legacy Redis `expired` reservations.
