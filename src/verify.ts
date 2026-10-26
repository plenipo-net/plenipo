import { calculateJwkThumbprint, decodeJwt, importJWK, jwtVerify } from 'jose';
import { mandateHash } from './encoding.js';
import { DelegationError, isSdJwtDelegation, verifyDelegateSdJwt, type DelegationFormat } from './delegate-sdjwt.js';
import { argsHash, chainHash } from './invocation.js';
import { nowSeconds } from './mandate.js';
import type { NonceStore, RevocationRegistry, SpendingLedger } from './registry.js';
import { idempotencyScope, requestFingerprint, type IdempotencyRecord, type IdempotencyStore } from './idempotency.js';
import type { RepresentationVerifyOptions } from './legal.js';
import { checkAttestationCertificates, checkAttestationStatus, checkPidStatus, RootError, verifyRoot, type EmandateVerifyOptions } from './root.js';
import { checkStatus, StatusUnavailableError, httpsOrigin, type StatusFetcher, type StatusListCache } from './status.js';
import { checkChainRevocation, TrustError, type TrustConfig } from './trust.js';
import type { CertificateRevocationOptions } from './x509-revocation.js';
import {
  allowsDelegation,
  anyActionCovers,
  attenuationViolations,
  counterpartyAllowed,
  validateInvocationPayload,
  validateMandate,
  MAX_DEPTH,
  type PolicyOptions,
} from './scope.js';
import {
  DELEGATION_TYP,
  INVOCATION_TYP,
  type Amount,
  type Decision,
  type DelegationPayload,
  type DenyCode,
  type InvocationPayload,
  type Mandate,
  type MandateChain,
  type PathEntry,
  type TrustedIssuer,
} from './types.js';

export interface VerifyOptions {
  /** PID providers trusted by explicit key. Use this or `trustAnchors`, or both. */
  trustedIssuers?: TrustedIssuer[];
  /** PEM certificates of the CAs on the PID provider trusted lists; PIDs are trusted through their x5c chain. */
  trustAnchors?: string[];
  /** Certificate policy OIDs the PID provider certificate must carry; see `TrustConfig.requiredPolicyOids`. */
  requiredPolicyOids?: string[];
  /** Extended key usage OIDs the PID provider certificate must carry when it has an EKU; see `TrustConfig.requiredEkus`. */
  requiredEkus?: string[];
  /** Checks the PID status list when the PID has one. Default `check`; `skip` only for offline tests. */
  pidStatus?: 'check' | 'skip';
  /** Who may sign the PID status list when it is not the PID provider; see `RootOptions.pidStatusTrust`. */
  pidStatusTrust?: TrustConfig;
  /** Refuse PIDs without a status list entry, unless their provider opts out; see `RootOptions.requirePidStatus`. Default true. */
  requirePidStatus?: boolean;
  /** x5c-trusted PID providers whose PIDs carry no status entry; see `RootOptions.pidProvidersWithoutStatus`. */
  pidProvidersWithoutStatus?: string[];
  /**
   * CRL/OCSP checking of the PID provider certificate path (and of the PID status list signer when it is
   * trusted under the same anchors). Default off. It runs after the invocation and scope checks, like status
   * lists, so an unauthenticated caller causes no network traffic. `hard-fail` is recommended in production.
   */
  certificateRevocation?: CertificateRevocationOptions;
  /**
   * Who may sign the status lists that mandates point to. Required when a mandate carries `status`.
   * The signer must be named for the status list origin (its `iss` in `trustedIssuers`, or a certificate
   * naming the origin), and lists are fetched only from `statusOrigins`, or from the origins of
   * `trustedIssuers` when `statusOrigins` is absent. Any other URI is refused without a request.
   */
  mandateStatusTrust?: TrustConfig;
  /**
   * Agent platforms whose wallet requests this relying party accepts, as key binding `aud` values
   * (the OpenID4VP client_id). When absent, a root obtained by any platform is accepted.
   */
  acceptedRootAudiences?: string[];
  /** Fetches status list tokens. Default: HTTPS GET. */
  statusFetcher?: StatusFetcher;
  statusCache?: StatusListCache;
  /**
   * Maximum age, in seconds, of a cached status list (PID, attestations, mandates) for this verification.
   * A cached list obtained earlier is fetched again, and the fetcher asks HTTP caches for a copy no older
   * than that. Set it on calls that move money, so a revocation takes effect within this bound instead of
   * the cache lifetime; `0` checks the origin on every call. Default: the cache decides.
   */
  maxStatusAgeSeconds?: number;
  /**
   * Keeps idempotency keys (see `src/idempotency.ts`). Needed to accept an invocation that carries `idem`:
   * without a store the key would have no effect and a retry would run again, so such an invocation is
   * refused with CONFIGURATION. On ALLOW the decision carries `idempotency`, the attempt the caller must end.
   */
  idempotency?: IdempotencyStore;
  /** This relying party's identifier; must equal the invocation `aud`. */
  audience: string;
  /** Single-use nonce store. Required: without it a captured invocation could be replayed. */
  nonces: NonceStore;
  /** Current time in seconds; defaults to now. */
  now?: number;
  /** Maximum age of an invocation in seconds. Default 120. */
  maxInvocationAgeSeconds?: number;
  /** Clock skew tolerated on `nbf` and invocation `iat`, in seconds. Default 60. Never applied to `exp`. */
  skewSeconds?: number;
  revocation?: RevocationRegistry;
  /** Required when any mandate in the chain has a total limit. */
  ledger?: SpendingLedger;
  policy?: PolicyOptions;
  acceptedPidVcts?: string[];
  /** PID claims the wallet must have disclosed, e.g. ['given_name', 'family_name']. */
  requiredPrincipalClaims?: string[];
  /**
   * What the relying party is actually about to do. Each field given must match the invocation exactly.
   * Use it whenever the invocation is not checked against the call by other means.
   */
  expected?: {
    action?: string;
    /**
     * The counterparty of the call, or `null` to declare that the operation has none (a balance read,
     * blocking a card). With `null` the invocation must not declare a counterparty. Counterparty
     * restrictions of the mandates are lifted only when `amount` is `null` too: a call that may move money
     * under a mandate restricted to some counterparties is refused (COUNTERPARTY_NOT_PERMITTED), since money
     * that leaves without a payee the relying party can name could go anywhere (a card top-up, fund units).
     */
    counterparty?: string | null;
    /**
     * The amount of the call, or `null` to declare that the operation moves no money. With `null` the
     * invocation must not declare an amount, and no spending limit of the chain applies to this call: no
     * per-operation check, no total, no reservation. Declare `null` only for operations that cannot move
     * money in any way; the relying party is the one that knows.
     */
    amount?: Amount | null;
    args?: unknown;
  };
  /** How TS12 e-mandate roots are accepted; see `EmandateVerifyOptions`. */
  emandate?: EmandateVerifyOptions;
  /** Trust and policy for representation attestations; required for mandates on behalf of a legal person. */
  representation?: RepresentationVerifyOptions;
  /**
   * Delegation link formats accepted in a chain. Default `['jws']`. Add `'sd-jwt'` to accept Delegate
   * SD-JWT links, which are experimental (see `plenipo/experimental`).
   */
  delegationFormats?: DelegationFormat[];
}

class Deny extends Error {
  constructor(
    readonly code: DenyCode,
    message: string,
    readonly at?: number,
    /** Internal detail for logs; never sent to the caller by the MCP guard. */
    readonly detail?: string,
    /** With ALREADY_EXECUTED: the stored result of the attempt that ran. */
    readonly replay?: { result?: string },
  ) {
    super(message);
  }
}

/** The part of a shared ledger that tells what became of a reservation (Postgres and Redis ledgers have it). */
interface ReservationLookup {
  reservation(id: string): Promise<{ state: string } | undefined>;
}

function canLookUp(ledger: SpendingLedger | undefined): ledger is SpendingLedger & ReservationLookup {
  return typeof (ledger as Partial<ReservationLookup> | undefined)?.reservation === 'function';
}

/**
 * Claims the idempotency key of an invocation for this attempt, or explains why it cannot run. A key held by
 * an attempt of unknown outcome follows the ledger when it can: a committed reservation means the action
 * ran, a released one means it did not (the ledger releases only on certainty), which frees the key.
 */
async function claimIdempotencyKey(
  store: IdempotencyStore,
  key: string,
  fingerprint: string,
  ledger: SpendingLedger | undefined,
  consumeNonce: () => Promise<void>,
): Promise<{ key: string; attempt: string }> {
  const alreadyExecuted = async (record: IdempotencyRecord | undefined): Promise<never> => {
    // The retry is a fresh invocation: burning its nonce keeps a copied retry from reading the result again.
    await consumeNonce();
    throw new Deny('ALREADY_EXECUTED', 'an earlier attempt with this idempotency key already executed', undefined, undefined, {
      ...(record?.result !== undefined ? { result: record.result } : {}),
    });
  };
  for (let round = 0; round < 2; round++) {
    const claim = await store.claim(key, fingerprint);
    if (claim.claimed) return { key, attempt: claim.attempt };
    const record = claim.record;
    if (record.fingerprint !== fingerprint) {
      throw new Deny('IDEMPOTENCY_CONFLICT', 'the idempotency key was already used for a different request');
    }
    if (record.state === 'executed') return alreadyExecuted(record);
    if (record.state === 'in_progress') {
      throw new Deny('IDEMPOTENCY_IN_PROGRESS', 'an attempt with this idempotency key is still running');
    }
    // Unknown outcome, or an abandoned attempt.
    if (record.reservation !== undefined && canLookUp(ledger)) {
      const info = await ledger.reservation(record.reservation);
      if (info?.state === 'committed') {
        await store.resolve(key, 'executed');
        return alreadyExecuted(undefined);
      }
      if (info?.state === 'released') {
        await store.resolve(key, 'not_executed');
        continue;
      }
    }
    throw new Deny('IDEMPOTENCY_UNRESOLVED', 'the outcome of an earlier attempt with this idempotency key is not known yet');
  }
  // The key was freed and taken again by a concurrent attempt in between.
  throw new Deny('IDEMPOTENCY_IN_PROGRESS', 'an attempt with this idempotency key is still running');
}

function statusOriginsOf(trust: TrustConfig): string[] {
  if (trust.statusOrigins) return trust.statusOrigins;
  return (trust.trustedIssuers ?? []).map((t) => httpsOrigin(t.iss)).filter((o): o is string => o !== undefined);
}

/** Payload members of a JWS delegation. */
const JWS_DELEGATION_MEMBERS = ['mandate', 'parent_id', 'parent_hash', 'iat'];

function entry(m: Mandate, depth: number): PathEntry {
  return { depth, mandate_id: m.id, actions: m.actions, exp: m.exp };
}

/**
 * Verifies a mandate chain and an invocation, and decides whether the agent may act.
 * Never throws for authorization failures: it returns DENY with a code and a reason.
 * On ALLOW with a `reservation`, the caller must commit or release it on the ledger.
 */
export async function verifyAuthorization(
  chain: MandateChain,
  invocation: string,
  opts: VerifyOptions,
): Promise<Decision> {
  const path: PathEntry[] = [];
  try {
    if (!opts?.nonces) throw new Deny('CONFIGURATION', 'a nonce store is required to prevent replay');
    const maxStatusAge = opts.maxStatusAgeSeconds;
    if (maxStatusAge !== undefined && (typeof maxStatusAge !== 'number' || !Number.isFinite(maxStatusAge) || maxStatusAge < 0)) {
      throw new Deny('CONFIGURATION', 'maxStatusAgeSeconds must be a non-negative number of seconds');
    }
    const statusAge = maxStatusAge !== undefined ? { maxStatusAgeSeconds: maxStatusAge } : {};
    const now = opts.now ?? nowSeconds();
    const skew = opts.skewSeconds ?? 60;
    // A nonce must be remembered for as long as an invocation carrying it can still be accepted.
    const retention = opts.nonces.retentionSeconds;
    if (typeof retention === 'number' && retention < (opts.maxInvocationAgeSeconds ?? 120) + skew) {
      throw new Deny('CONFIGURATION', 'the nonce store forgets nonces before invocations expire');
    }

    if (!chain || typeof chain !== 'object' || !Array.isArray(chain.delegations)) {
      throw new Deny('MALFORMED', 'chain must have root and delegations');
    }
    if (chain.delegations.length > MAX_DEPTH) throw new Deny('MALFORMED', `chain longer than ${MAX_DEPTH} delegations`);
    if (typeof invocation !== 'string') throw new Deny('MALFORMED', 'invocation must be a compact JWS');

    // 1. Root
    let root;
    try {
      root = await verifyRoot(chain.root, {
        trustedIssuers: opts.trustedIssuers,
        trustAnchors: opts.trustAnchors,
        requiredPolicyOids: opts.requiredPolicyOids,
        requiredEkus: opts.requiredEkus,
        now,
        acceptedVcts: opts.acceptedPidVcts,
        skewSeconds: skew,
        pidStatus: opts.pidStatus === 'skip' ? 'skip' : 'defer',
        requirePidStatus: opts.requirePidStatus,
        pidProvidersWithoutStatus: opts.pidProvidersWithoutStatus,
        statusFetcher: opts.statusFetcher,
        statusCache: opts.statusCache,
        emandate: opts.emandate,
        representation: opts.representation,
        attestationStatus: 'defer',
      });
    } catch (e) {
      if (e instanceof RootError) throw new Deny(e.code, e.message, 0, e.detail);
      throw e;
    }
    if (opts.acceptedRootAudiences && !opts.acceptedRootAudiences.includes(root.keyBinding.aud as string)) {
      throw new Deny('ROOT_INVALID', 'the root was obtained by a platform this service does not accept', 0);
    }
    const rootProblems = validateMandate(root.mandate, opts.policy);
    if (rootProblems.length) {
      const code: DenyCode = rootProblems.some((p) => p.includes('lifetime')) ? 'LIFETIME_POLICY' : 'MALFORMED';
      throw new Deny(code, `root mandate: ${rootProblems.join('; ')}`, 0);
    }
    if (root.pidExp !== undefined && root.mandate.exp > root.pidExp) {
      throw new Deny('LIFETIME_POLICY', 'root mandate outlives the PID that authorised it', 0);
    }
    for (const claim of opts.requiredPrincipalClaims ?? []) {
      if (root.principal[claim] === undefined) throw new Deny('ROOT_INVALID', `the wallet did not disclose ${claim}`, 0);
    }
    const mandates: Mandate[] = [root.mandate];
    path.push(entry(root.mandate, 0));

    // 2. Delegations
    for (let i = 0; i < chain.delegations.length; i++) {
      const depth = i + 1;
      const parent = mandates[i];
      let payload: DelegationPayload;
      const token = chain.delegations[i];
      if (isSdJwtDelegation(token)) {
        if (!(opts.delegationFormats ?? ['jws']).includes('sd-jwt')) {
          throw new Deny('MALFORMED', `delegation ${depth} is a Delegate SD-JWT, which this verifier does not accept`, depth);
        }
        try {
          payload = await verifyDelegateSdJwt(token, parent.agent.jwk);
        } catch (e) {
          if (!(e instanceof DelegationError)) throw e;
          const reason = e.code === 'MALFORMED' ? `delegation ${depth}: ${e.message}` : `delegation ${depth} is not signed by the parent agent: ${e.message}`;
          throw new Deny(e.code, reason, depth, e.detail);
        }
      } else {
        try {
          const key = await importJWK(parent.agent.jwk, 'ES256');
          const res = await jwtVerify(token, key, { typ: DELEGATION_TYP, algorithms: ['ES256'] });
          payload = res.payload as unknown as DelegationPayload;
        } catch (e) {
          throw new Deny('DELEGATION_SIGNATURE_INVALID', `delegation ${depth} is not signed by the parent agent`, depth, (e as Error)?.message);
        }
        // As for SD-JWT links: a member the verifier does not know could be a constraint it would ignore.
        const extra = Object.keys(payload).filter((k) => !JWS_DELEGATION_MEMBERS.includes(k));
        if (extra.length) throw new Deny('MALFORMED', `delegation ${depth}: unknown member ${extra.join(', ')}`, depth);
      }
      if (payload.parent_id !== parent.id || payload.parent_hash !== mandateHash(parent)) {
        throw new Deny('DELEGATION_PARENT_MISMATCH', `delegation ${depth} does not refer to its parent mandate`, depth);
      }
      const child = payload.mandate;
      // Only the root says on whose behalf the agent acts; a delegator cannot restate or change it.
      if (child && typeof child === 'object' && 'principal' in child) {
        throw new Deny('ATTENUATION_VIOLATION', `delegation ${depth} may not set a principal`, depth);
      }
      const problems = validateMandate(child, opts.policy);
      if (problems.length) throw new Deny('MALFORMED', `mandate ${depth}: ${problems.join('; ')}`, depth);
      if (!allowsDelegation(parent)) {
        throw new Deny('DELEGATION_NOT_ALLOWED', `mandate ${depth - 1} does not allow sub-delegation`, depth);
      }
      const violations = attenuationViolations(parent, child);
      if (violations.length) throw new Deny('ATTENUATION_VIOLATION', `delegation ${depth}: ${violations.join('; ')}`, depth);
      mandates.push(child);
      path.push(entry(child, depth));
    }

    // 3. Time. Skew helps a slightly early clock on nbf, but a mandate is never used after exp.
    for (let i = 0; i < mandates.length; i++) {
      if (now + skew < mandates[i].nbf) throw new Deny('NOT_YET_VALID', `mandate ${i} is not valid yet`, i);
      if (now >= mandates[i].exp) throw new Deny('EXPIRED', `mandate ${i} has expired`, i);
    }

    // 4. Revocation in the local registry. Status lists need network access and come after the
    //    invocation and scope checks, so an unauthenticated caller cannot make this service fetch URLs.
    for (let i = 0; i < mandates.length; i++) {
      const m = mandates[i];
      if (opts.revocation && (await opts.revocation.isRevoked(m.id))) {
        throw new Deny('REVOKED', `mandate ${i} (${m.id}) has been revoked`, i);
      }
      if (m.status) {
        const trust = opts.mandateStatusTrust;
        if (!trust?.trustedIssuers?.length && !trust?.trustAnchors?.length) {
          throw new Deny('CONFIGURATION', `mandate ${i} has a status list and mandateStatusTrust is not configured`, i);
        }
      }
    }

    // 5. Invocation: signature, then strict shape, then binding to this relying party and call.
    const leaf = mandates[mandates.length - 1];
    let inv: InvocationPayload;
    try {
      const key = await importJWK(leaf.agent.jwk, 'ES256');
      const res = await jwtVerify(invocation, key, { typ: INVOCATION_TYP, algorithms: ['ES256'] });
      inv = res.payload as unknown as InvocationPayload;
    } catch (e) {
      throw new Deny('INVOCATION_SIGNATURE_INVALID', 'invocation is not signed by the leaf agent', undefined, (e as Error)?.message);
    }
    const shape = validateInvocationPayload(inv);
    if (shape.length) throw new Deny('MALFORMED', `invocation: ${shape.join('; ')}`);
    if (inv.mandate !== leaf.id) throw new Deny('INVOCATION_MANDATE_MISMATCH', 'invocation refers to a different mandate');
    // Mandate ids are chosen by delegators and public, so the id alone does not tie the invocation to this
    // chain: an agent key used in two chains could have its invocation replayed on the other one.
    if (typeof inv.chain_hash !== 'string' || inv.chain_hash !== chainHash(chain)) {
      throw new Deny('INVOCATION_MANDATE_MISMATCH', 'invocation was not signed for this mandate chain');
    }
    if (inv.aud !== opts.audience) throw new Deny('AUDIENCE_MISMATCH', `invocation is for ${inv.aud}, not ${opts.audience}`);
    const maxAge = opts.maxInvocationAgeSeconds ?? 120;
    if (inv.iat > now + skew || now - inv.iat > maxAge) {
      throw new Deny('INVOCATION_STALE', 'invocation is too old or from the future');
    }
    const ex = opts.expected;
    if (ex) {
      if (ex.action !== undefined && inv.action !== ex.action) {
        throw new Deny('INVOCATION_MISMATCH', `invocation is for ${inv.action}, the call performs ${ex.action}`);
      }
      if (ex.counterparty === null) {
        if (inv.counterparty !== undefined) throw new Deny('INVOCATION_MISMATCH', 'invocation declares a counterparty the call does not have');
      } else if (ex.counterparty !== undefined && inv.counterparty !== ex.counterparty) {
        throw new Deny('INVOCATION_MISMATCH', 'invocation counterparty does not match the call');
      }
      if (ex.amount === null) {
        if (inv.amount !== undefined) throw new Deny('INVOCATION_MISMATCH', 'invocation declares an amount the call does not move');
      } else if (ex.amount !== undefined && (inv.amount?.value !== ex.amount.value || inv.amount?.currency !== ex.amount.currency)) {
        throw new Deny('INVOCATION_MISMATCH', 'invocation amount does not match the call');
      }
      if (ex.args !== undefined && inv.args_hash !== argsHash(ex.args)) {
        throw new Deny('INVOCATION_MISMATCH', 'invocation does not match the call arguments');
      }
    }

    // 6. Scope, on every mandate of the chain. Counterparty and spending limits are skipped only when the
    //    relying party itself declared that the call has no counterparty or moves no money (see `expected`).
    const noMoney = ex?.amount === null;
    // Lifting counterparty restrictions on a call that moves money would let a "no payee" route spend
    // under a mandate restricted to a few payees, so `counterparty: null` counts only together with `amount: null`.
    const noCounterparty = ex?.counterparty === null && noMoney;
    let needsLedger = false;
    for (let i = 0; i < mandates.length; i++) {
      const m = mandates[i];
      if (!anyActionCovers(m.actions, inv.action)) {
        throw new Deny('ACTION_NOT_PERMITTED', `action ${inv.action} is outside mandate ${i}`, i);
      }
      if (m.counterparties && !noCounterparty) {
        if (ex?.counterparty === null) {
          throw new Deny('COUNTERPARTY_NOT_PERMITTED', `mandate ${i} restricts counterparties and the call may move money without one`, i);
        }
        if (!inv.counterparty || !counterpartyAllowed(m.counterparties, inv.counterparty)) {
          throw new Deny('COUNTERPARTY_NOT_PERMITTED', `counterparty ${String(inv.counterparty)} is outside mandate ${i}`, i);
        }
      }
      if (m.limits && !noMoney) {
        if (!inv.amount) throw new Deny('LIMIT_PER_OPERATION', `mandate ${i} has spending limits and the invocation declares no amount`, i);
        if (inv.amount.currency !== m.limits.currency) {
          throw new Deny('CURRENCY_MISMATCH', `invocation currency ${inv.amount.currency} differs from mandate ${i}`, i);
        }
        if (m.limits.per_operation !== undefined && inv.amount.value > m.limits.per_operation) {
          throw new Deny('LIMIT_PER_OPERATION', `amount ${inv.amount.value} exceeds ${m.limits.per_operation} on mandate ${i}`, i);
        }
        if (m.limits.total !== undefined) needsLedger = true;
      }
    }
    if (needsLedger && !opts.ledger) throw new Deny('CONFIGURATION', 'the chain has a total limit and no ledger is configured');

    // 6b. Revocation of the PID provider certificate, then status lists: the PID, then every mandate that has one.
    const certRevocation = opts.certificateRevocation;
    if (certRevocation && certRevocation.policy !== 'off' && root.pidCertificateChain) {
      try {
        await checkChainRevocation(root.pidCertificateChain, certRevocation, now);
      } catch (e) {
        if (e instanceof TrustError) throw new Deny('PID_ISSUER_UNTRUSTED', 'PID provider certificate is revoked or its status could not be verified', 0, e.message);
        throw e;
      }
    }
    if (root.pidStatus) {
      try {
        await checkPidStatus(root.pidStatus, root.pidIssuer, {
          trustedIssuers: opts.trustedIssuers,
          trustAnchors: opts.trustAnchors,
          requiredPolicyOids: opts.requiredPolicyOids,
          requiredEkus: opts.requiredEkus,
          pidStatusTrust: opts.pidStatusTrust,
          ...(certRevocation ? { certificateRevocation: certRevocation } : {}),
          now,
          statusFetcher: opts.statusFetcher,
          statusCache: opts.statusCache,
          ...statusAge,
        });
      } catch (e) {
        if (e instanceof RootError) throw new Deny(e.code, e.message, 0, e.detail);
        throw e;
      }
    }
    for (const c of root.deferredCertificates ?? []) {
      try {
        await checkAttestationCertificates(c, now);
      } catch (e) {
        if (e instanceof RootError) throw new Deny(e.code, e.message, 0, e.detail);
        throw e;
      }
    }
    for (const d of root.deferredStatus ?? []) {
      try {
        await checkAttestationStatus(d, { now, statusFetcher: opts.statusFetcher, statusCache: opts.statusCache, ...statusAge });
      } catch (e) {
        if (e instanceof RootError) throw new Deny(e.code, e.message, 0, e.detail);
        throw e;
      }
    }
    for (let i = 0; i < mandates.length; i++) {
      const m = mandates[i];
      if (!m.status) continue;
      const trust = opts.mandateStatusTrust!;
      let status: number;
      try {
        status = await checkStatus(m.status, {
          trust,
          signer: httpsOrigin(m.status.status_list.uri) ?? '',
          allowedOrigins: statusOriginsOf(trust),
          fetcher: opts.statusFetcher,
          now,
          cache: opts.statusCache,
          ...(maxStatusAge !== undefined ? { maxAgeSeconds: maxStatusAge } : {}),
        });
      } catch (e) {
        throw new Deny(e instanceof StatusUnavailableError ? 'STATUS_UNAVAILABLE' : 'REVOKED', `status of mandate ${i} could not be verified`, i, (e as Error).message);
      }
      if (status !== 0) throw new Deny('REVOKED', `mandate ${i} is ${status === 2 ? 'suspended' : 'revoked'} in its status list`, i);
    }

    // 7. Idempotency. After every check that can refuse the call, so a refused attempt never claims or blocks
    //    a key; before the reservation, so the retry of an executed call is answered from its record instead
    //    of reserving again.
    let nonceConsumed = false;
    const consumeNonce = async (): Promise<void> => {
      const fresh = await opts.nonces.consume(inv.nonce);
      if (!fresh) throw new Deny('REPLAY', 'invocation nonce was already used or was not issued');
      nonceConsumed = true;
    };
    let idem: { key: string; attempt: string } | undefined;
    if (inv.idem !== undefined) {
      if (!opts.idempotency) {
        throw new Deny('CONFIGURATION', 'the invocation carries an idempotency key and this service keeps no idempotency store');
      }
      idem = await claimIdempotencyKey(
        opts.idempotency,
        idempotencyScope(opts.audience, inv.chain_hash, inv.idem),
        requestFingerprint(inv),
        opts.ledger,
        consumeNonce,
      );
    }

    // Until ALLOW is returned nothing has run: every failure below gives the reservation and the key back.
    let reservation: string | undefined;
    try {
      // 8. Atomic reservation against every total limit in the chain.
      if (needsLedger && inv.amount && opts.ledger) {
        const entries = mandates.map((m) => ({ key: mandateHash(m), total: m.limits?.total }));
        const r = await opts.ledger.reserve(entries, inv.amount);
        if (r === null) throw new Deny('LIMIT_TOTAL', `amount ${inv.amount.value} would exceed a total limit in the chain`);
        reservation = r;
        if (idem) await opts.idempotency!.attach(idem.key, idem.attempt, r);
      }
      // 9. Replay. Checked last, so a denied invocation does not burn its nonce.
      if (!nonceConsumed) await consumeNonce();
    } catch (e) {
      // Best effort: the original failure is what the caller must see. A reservation left pending keeps
      // counting (safe side); a key left in progress turns unresolved after the lease (safe side too).
      const ledger = opts.ledger;
      const store = opts.idempotency;
      if (reservation && ledger) await Promise.resolve().then(() => ledger.release(reservation!)).catch(() => undefined);
      if (idem && store) await store.finish(idem.key, idem.attempt, 'not_executed').catch(() => undefined);
      throw e;
    }

    return {
      decision: 'ALLOW',
      principal: (root.legalPrincipal as unknown as Record<string, unknown>) ?? root.principal,
      ...(root.representation ? { representation: root.representation } : {}),
      ...(root.binding ? { root_binding: root.binding } : {}),
      pid_issuer: root.pidIssuer,
      pid_trusted_via: root.trustedVia,
      path,
      mandates,
      invocation: inv,
      ...(reservation ? { reservation } : {}),
      ...(idem ? { idempotency: idem } : {}),
      // Never throws: the reservation above must not be left behind by an identifier for policy engines.
      ...(root.holderJwk ? await calculateJwkThumbprint(root.holderJwk, 'sha256').then((t) => ({ pid_holder_jkt: t }), () => ({})) : {}),
    };
  } catch (e) {
    if (e instanceof Deny) {
      return {
        decision: 'DENY',
        code: e.code,
        reason: e.message,
        ...(e.at !== undefined ? { at: e.at } : {}),
        ...(e.detail !== undefined ? { detail: e.detail } : {}),
        ...(e.replay !== undefined ? { replay: e.replay } : {}),
        path,
      };
    }
    return { decision: 'DENY', code: 'INTERNAL', reason: 'the request could not be processed', detail: (e as Error)?.message ?? String(e), path };
  }
}

/** Reads the invocation payload without verifying it, for logging and routing only. */
export function peekInvocation(invocation: string): InvocationPayload {
  return decodeJwt(invocation) as unknown as InvocationPayload;
}
