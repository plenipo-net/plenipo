/**
 * Append-only, hash-chained audit log of authorization decisions, for disputes and supervisory audits.
 *
 * Every record carries the hash of the previous one, so editing, deleting or reordering a record breaks
 * the chain. Records can be signed one by one or at checkpoints; a signature on record n vouches for every
 * record up to n. Truncating the tail is only detectable against a head kept elsewhere (`expectedHead`):
 * a log cut back to an earlier signed record still verifies, signatures included.
 */
import { signCompactJwt, type SigningKey } from './signer.js';
import { open, readFile } from 'node:fs/promises';
import { importJWK, jwtVerify, type CryptoKey, type JWK } from 'jose';
import { canonicalize, sha256 } from './encoding.js';
import type { Decision, MandateChain } from './types.js';
import { isLegalPersonPrincipal, principalIdentity } from './principal.js';

export const AUDIT_RECORD_VERSION = 1;
export const AUDIT_SIGNATURE_TYP = 'plenipo-audit+jwt';
/** `prev` of the first record of a log. */
export const AUDIT_GENESIS = 'A'.repeat(43);

export type AuditEvent = 'decision' | 'settlement' | 'status_change' | 'checkpoint';

export interface AuditRecord {
  v: typeof AUDIT_RECORD_VERSION;
  seq: number;
  /** ISO 8601 time the record was written. */
  ts: string;
  /** Hash of the previous record, or AUDIT_GENESIS. */
  prev: string;
  event: AuditEvent;
  decision?: 'ALLOW' | 'DENY';
  /** DenyCode from the verifier, when it produced the decision. */
  code?: string;
  /** Problem code sent to the caller, for denials. */
  problem?: string;
  /** Internal reason; never sent to callers, kept here for investigations. */
  reason?: string;
  /** Internal detail (network errors etc.), when `includeDetail` is on. */
  detail?: string;
  /** Mandate ids from the root (index 0) to the deepest mandate verified. */
  mandate_ids?: string[];
  /** SHA-256 (base64url) of the compact invocation JWS. */
  invocation_hash?: string;
  /** The verified invocation claims (ALLOW only). */
  invocation?: Record<string, unknown>;
  /**
   * Minimised principal (ALLOW only): the kept PID claims for a natural person; for a legal person
   * `{ type: 'legal_person', euid, legal_name?, role, representative: <kept PID claims> }`.
   */
  principal?: Record<string, unknown>;
  /** Stable, non-readable identifier of the natural person who approved (see src/principal.ts). */
  principal_id?: string;
  pid_issuer?: string;
  reservation?: string;
  /**
   * `commit` and `release` are final. `pending` means the outcome of the action is not known (API error,
   * timeout, client gone): the reservation stays pending until it is reconciled or swept as spent.
   */
  settlement?: 'commit' | 'release' | 'pending';
  http?: { method?: string; path?: string; status?: number };
  /** Free-form, JSON-serialisable context from the integrator. */
  context?: Record<string, unknown>;
  /** Evidence, when configured: the compact invocation and/or the full chain. */
  evidence?: { invocation?: string; chain?: MandateChain };
  /** SHA-256 (base64url) of the canonical record without `hash` and `sig`. */
  hash: string;
  /** Compact JWS over `{ seq, hash }`, present on signed records. */
  sig?: string;
}

/** What callers provide; the log fills in v, seq, ts, prev, hash and sig. */
export type AuditEntry = Omit<AuditRecord, 'v' | 'seq' | 'ts' | 'prev' | 'hash' | 'sig'>;

/** Persistence for audit records. A store has exactly one writer: the AuditLog that owns it. */
export interface AuditStore {
  /** The last record, so a restarted log continues the chain. */
  last(): Promise<AuditRecord | undefined>;
  /** Appends one record durably, after every record appended before it. */
  append(record: AuditRecord): Promise<void>;
  /** Every record, in order. */
  readAll(): Promise<AuditRecord[]>;
}

export class InMemoryAuditStore implements AuditStore {
  private readonly records: AuditRecord[] = [];
  async last(): Promise<AuditRecord | undefined> {
    return this.records[this.records.length - 1];
  }
  async append(record: AuditRecord): Promise<void> {
    this.records.push(structuredClone(record));
  }
  async readAll(): Promise<AuditRecord[]> {
    return structuredClone(this.records);
  }
}

/**
 * One JSON record per line. With `fsync` each append is flushed to stable storage before it resolves,
 * which is what an audit trail used in disputes should have; without it a crash may lose the latest records.
 */
export class JsonlFileAuditStore implements AuditStore {
  constructor(
    readonly path: string,
    private readonly opts: { fsync?: boolean } = {},
  ) {}

  private async lines(): Promise<string[]> {
    let text: string;
    try {
      text = await readFile(this.path, 'utf8');
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === 'ENOENT') return [];
      throw e;
    }
    const lines = text.split('\n');
    // A file written by this store ends with a newline; anything after the last one is a torn write.
    if (lines[lines.length - 1] !== '') throw new Error('audit file ends with an incomplete record');
    lines.pop();
    return lines;
  }

  async last(): Promise<AuditRecord | undefined> {
    const lines = await this.lines();
    return lines.length ? (JSON.parse(lines[lines.length - 1]) as AuditRecord) : undefined;
  }

  async append(record: AuditRecord): Promise<void> {
    const fh = await open(this.path, 'a', 0o600);
    try {
      await fh.appendFile(JSON.stringify(record) + '\n', 'utf8');
      if (this.opts.fsync) await fh.sync();
    } finally {
      await fh.close();
    }
  }

  async readAll(): Promise<AuditRecord[]> {
    return (await this.lines()).map((l) => JSON.parse(l) as AuditRecord);
  }
}

export interface AuditRedaction {
  /**
   * PID claims kept in decision records. Default `['given_name', 'family_name']`. `'all'` keeps every
   * disclosed claim; `[]` keeps none. The PID issuer is always kept.
   */
  principalClaims?: string[] | 'all';
  /**
   * Evidence kept with ALLOW decisions. `invocation` (default) keeps the compact invocation JWS, which holds
   * no personal data and proves what the agent signed. `full` also keeps the mandate chain, including the PID
   * presentation: use it only with a documented legal basis. `none` keeps only hashes.
   */
  evidence?: 'none' | 'invocation' | 'full';
  /** Keep the verifier's internal `detail` (network and library errors). Default true, truncated to 512 characters. */
  includeDetail?: boolean;
  /** Claims that identify a person uniquely, for `principal_id`. Default `['personal_administrative_number']`. */
  principalIdClaims?: string[];
}

export interface AuditSigner {
  /** Private key or external signer (KMS, HSM); ES256 by default. */
  key: SigningKey;
  alg?: 'ES256' | 'ES384' | 'EdDSA';
  kid?: string;
  /** Sign every record (default), or only every n-th record. `checkpoint()` signs on demand. */
  every?: number;
}

export interface AuditLogOptions {
  store: AuditStore;
  redaction?: AuditRedaction;
  signer?: AuditSigner;
  /** Clock, for tests. */
  now?: () => Date;
}

export interface DecisionAuditInput {
  /** The verifier's decision; absent when the request was refused before verification. */
  decision?: Decision;
  /** Problem code sent to the caller, for denials. */
  problem?: string;
  /** Internal reason when there is no decision (gateway refusals). */
  reason?: string;
  /** The compact invocation as presented, if any. */
  invocation?: string;
  chain?: MandateChain;
  /** Mandate ids when there is no verifier decision to take them from. */
  mandateIds?: string[];
  http?: { method?: string; path?: string; status?: number };
  context?: Record<string, unknown>;
}

const DEFAULT_PRINCIPAL_CLAIMS = ['given_name', 'family_name'];
const MAX_DETAIL = 512;
const MAX_STRING = 64 * 1024;
/** Invocation claims kept in ALLOW records; anything else the agent put in the payload is left out. */
const INVOCATION_CLAIMS = ['mandate', 'action', 'counterparty', 'amount', 'aud', 'nonce', 'iat', 'args_hash', 'chain_hash'];

function knownInvocationClaims(inv: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const k of INVOCATION_CLAIMS) {
    const v = inv[k];
    if (v === undefined) continue;
    if (k === 'amount') {
      const a = v as Record<string, unknown> | null;
      if (a && typeof a === 'object') out.amount = { value: a.value, currency: a.currency };
    } else if (typeof v === 'string' || typeof v === 'number') out[k] = v;
  }
  return out;
}

/**
 * Makes a value safe for RFC 8785 canonicalisation and bounded in size: lone surrogates become U+FFFD,
 * long strings are cut, non-finite numbers become null, and anything that is not JSON is dropped.
 */
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g;
const wellFormed = (s: string) => s.replace(LONE_SURROGATE, '\uFFFD');

export function sanitizeForAudit(value: unknown, depth = 0): unknown {
  if (depth > 16) return null;
  if (typeof value === 'string') {
    const s = value.length > MAX_STRING ? value.slice(0, MAX_STRING) : value;
    return wellFormed(s);
  }
  if (typeof value === 'number') return Number.isFinite(value) ? value : null;
  if (typeof value === 'boolean' || value === null) return value;
  if (Array.isArray(value)) return value.map((v) => (v === undefined ? null : sanitizeForAudit(v, depth + 1)));
  if (typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (v === undefined || typeof v === 'function' || typeof v === 'symbol' || typeof v === 'bigint') continue;
      out[wellFormed(k)] = sanitizeForAudit(v, depth + 1);
    }
    return out;
  }
  return undefined;
}

function stripUndefined<T extends Record<string, unknown>>(o: T): T {
  return Object.fromEntries(Object.entries(o).filter(([, v]) => v !== undefined)) as T;
}

/** The hash of a record: SHA-256 of its RFC 8785 canonical form without `hash` and `sig`. */
export function auditRecordHash(record: Omit<AuditRecord, 'hash' | 'sig'> & { hash?: string; sig?: string }): string {
  const { hash: _h, sig: _s, ...rest } = record;
  return sha256(canonicalize(rest));
}

/** Writes audit records. Appends are serialised, so concurrent requests cannot fork the chain. */
export class AuditLog {
  private queue: Promise<unknown> = Promise.resolve();
  private head?: { seq: number; hash: string };

  constructor(private readonly opts: AuditLogOptions) {
    if (!opts?.store) throw new Error('AuditLog needs a store');
    const every = opts.signer?.every;
    if (every !== undefined && (!Number.isSafeInteger(every) || every < 1)) throw new Error('signer.every must be a positive integer');
  }

  /** Appends a record. Rejects when the store fails. */
  append(entry: AuditEntry, opts: { forceSign?: boolean } = {}): Promise<AuditRecord> {
    const run = this.queue.then(() => this.write(entry, opts.forceSign ?? false));
    this.queue = run.catch(() => undefined);
    return run;
  }

  private async write(entry: AuditEntry, forceSign: boolean): Promise<AuditRecord> {
    try {
      if (!this.head) {
        const last = await this.opts.store.last();
        this.head = last ? { seq: last.seq, hash: last.hash } : { seq: -1, hash: AUDIT_GENESIS };
      }
      // Every value is made canonicalisable first: an agent-chosen string with a lone surrogate, or a
      // non-finite number, must not make a decision unrecordable.
      const body = stripUndefined({
        ...(sanitizeForAudit(entry) as AuditEntry),
        v: AUDIT_RECORD_VERSION,
        seq: this.head.seq + 1,
        ts: (this.opts.now?.() ?? new Date()).toISOString(),
        prev: this.head.hash,
      }) as Omit<AuditRecord, 'hash' | 'sig'>;
      const hash = auditRecordHash(body);
      const record: AuditRecord = { ...body, hash };
      const s = this.opts.signer;
      if (s && (forceSign || (record.seq + 1) % (s.every ?? 1) === 0)) {
        record.sig = await signCompactJwt(
          { seq: record.seq, hash },
          { alg: s.alg ?? 'ES256', typ: AUDIT_SIGNATURE_TYP, ...(s.kid ? { kid: s.kid } : {}) },
          s.key,
        );
      }
      await this.opts.store.append(record);
      this.head = { seq: record.seq, hash };
      return record;
    } catch (e) {
      // The store may or may not hold the record now; re-read its head before the next append, so the chain
      // never forks. A torn JSONL line makes `last()` throw, and the log stays closed until it is repaired.
      this.head = undefined;
      throw e;
    }
  }

  /** Appends a signed checkpoint record, e.g. on a timer or at shutdown. Needs a signer. */
  checkpoint(context?: Record<string, unknown>): Promise<AuditRecord> {
    if (!this.opts.signer) return Promise.reject(new Error('checkpoints need a signer'));
    return this.append({ event: 'checkpoint', ...(context ? { context } : {}) }, { forceSign: true });
  }

  /** Records a decision, applying the configured redaction. */
  recordDecision(input: DecisionAuditInput): Promise<AuditRecord> {
    return this.append(this.decisionEntry(input));
  }

  /** Records whether a reservation was committed or released after the action. */
  recordSettlement(input: {
    reservation?: string;
    settlement: 'commit' | 'release' | 'pending';
    invocation?: string;
    http?: { method?: string; path?: string; status?: number };
    reason?: string;
    context?: Record<string, unknown>;
  }): Promise<AuditRecord> {
    return this.append({
      event: 'settlement',
      settlement: input.settlement,
      reservation: input.reservation,
      invocation_hash: input.invocation ? sha256(input.invocation) : undefined,
      http: input.http,
      reason: input.reason,
      context: input.context,
    });
  }

  private decisionEntry(input: DecisionAuditInput): AuditEntry {
    const r = this.opts.redaction ?? {};
    const d = input.decision;
    const evidence = r.evidence ?? 'invocation';
    const base: AuditEntry = {
      event: 'decision',
      decision: d?.decision ?? 'DENY',
      problem: input.problem,
      invocation_hash: input.invocation ? sha256(input.invocation) : undefined,
      mandate_ids: d ? d.path.map((p) => p.mandate_id) : input.mandateIds,
      http: input.http,
      context: input.context,
    };
    if (!d || d.decision === 'DENY') {
      const detail = d?.decision === 'DENY' && (r.includeDetail ?? true) && d.detail !== undefined ? d.detail.slice(0, MAX_DETAIL) : undefined;
      return stripUndefined({ ...base, code: d?.code, reason: d?.reason ?? input.reason, detail });
    }
    const keep = r.principalClaims ?? DEFAULT_PRINCIPAL_CLAIMS;
    const identity = principalIdentity(d, { principalClaims: keep, idClaims: r.principalIdClaims });
    // A legal person is recorded by its EUID, name and role, and the representative by the kept PID claims.
    const principal =
      identity.type === 'legal_person'
        ? {
            type: 'legal_person',
            euid: identity.euid,
            ...(identity.legal_name !== null ? { legal_name: identity.legal_name } : {}),
            role: identity.role,
            representative: identity.representative.claims,
          }
        : identity.claims;
    const ev =
      evidence === 'none' || !input.invocation
        ? undefined
        : { invocation: input.invocation, ...(evidence === 'full' && input.chain ? { chain: input.chain } : {}) };
    return stripUndefined({
      ...base,
      invocation: knownInvocationClaims(d.invocation as unknown as Record<string, unknown>),
      principal,
      principal_id: identity.type === 'legal_person' ? identity.representative.id : identity.id,
      pid_issuer: d.pid_issuer,
      reservation: d.reservation,
      evidence: ev,
    });
  }
}

export interface AuditVerifyOptions {
  /** Public key for record signatures. Without it signatures are not checked. */
  key?: CryptoKey | JWK;
  alg?: 'ES256' | 'ES384' | 'EdDSA';
  /** The record just before the first one given, for a log that was rotated or pruned after retention. */
  anchor?: { seq: number; hash: string };
  /** The head kept elsewhere (a published checkpoint, a WORM store): detects truncation of the tail. */
  expectedHead?: { seq: number; hash: string };
  /**
   * With a key, the default is `all`: every record must carry a valid signature, so a log rewritten without
   * the key fails even if its hashes were recomputed. For logs written with `signer.every > 1` or
   * checkpoints, use `head` after a checkpoint: the last record must be signed, and its signature covers
   * every earlier record through the hash chain. `none` checks only the signatures present and reports in
   * `unauthenticated` how many trailing records no signature covers. Without a key, signatures are not
   * checked and `all`/`head` fail.
   */
  requireSignatures?: 'none' | 'all' | 'head';
}

export type AuditVerifyResult =
  | {
      valid: true;
      count: number;
      head?: { seq: number; hash: string };
      signedThrough?: number;
      /** With a key: trailing records that no valid signature covers. */
      unauthenticated?: number;
    }
  | { valid: false; index: number; error: string };

/**
 * Checks a sequence of records: version, consecutive sequence numbers, the hash link to the previous record,
 * each record's own hash, and signatures when a key is given. Detects edits, deletions, insertions and
 * reordering anywhere but at the tail. Removal of trailing records is detected only with `expectedHead`: a
 * signed head proves the records up to it were written by the key holder, not that none followed.
 */
export async function verifyAuditLog(records: AuditRecord[], opts: AuditVerifyOptions = {}): Promise<AuditVerifyResult> {
  const require = opts.requireSignatures ?? (opts.key ? 'all' : 'none');
  if (require !== 'none' && !opts.key) return { valid: false, index: -1, error: 'signatures are required but no key was given' };
  const key = opts.key && 'kty' in opts.key ? await importJWK(opts.key as JWK, opts.alg ?? 'ES256') : (opts.key as CryptoKey | undefined);
  let prevSeq = opts.anchor ? opts.anchor.seq : -1;
  let prevHash = opts.anchor ? opts.anchor.hash : AUDIT_GENESIS;
  let signedThrough: number | undefined;
  for (let i = 0; i < records.length; i++) {
    const r = records[i];
    const bad = (error: string): AuditVerifyResult => ({ valid: false, index: i, error });
    if (typeof r !== 'object' || r === null || r.v !== AUDIT_RECORD_VERSION) return bad('unknown record version');
    if (!Number.isSafeInteger(r.seq) || typeof r.hash !== 'string' || typeof r.prev !== 'string') return bad('record is malformed');
    if (r.seq !== prevSeq + 1) return bad(`sequence ${r.seq} follows ${prevSeq}: records are missing or out of order`);
    if (r.prev !== prevHash) return bad('record does not link to the previous record');
    let recomputed: string;
    try {
      recomputed = auditRecordHash(r);
    } catch {
      return bad('record cannot be canonicalised');
    }
    if (recomputed !== r.hash) return bad('record hash does not match its content');
    if (r.sig !== undefined && key) {
      try {
        const { payload } = await jwtVerify(r.sig, key, { typ: AUDIT_SIGNATURE_TYP, algorithms: [opts.alg ?? 'ES256'] });
        if (payload.seq !== r.seq || payload.hash !== r.hash) return bad('signature covers another record');
      } catch {
        return bad('record signature is not valid');
      }
      signedThrough = r.seq;
    } else if (require === 'all') {
      return bad('record is not signed');
    }
    prevSeq = r.seq;
    prevHash = r.hash;
  }
  if (require === 'head' && records.length && signedThrough !== records[records.length - 1].seq) {
    return { valid: false, index: records.length - 1, error: 'the last record is not signed' };
  }
  if (opts.expectedHead && (opts.expectedHead.seq !== prevSeq || opts.expectedHead.hash !== prevHash)) {
    return { valid: false, index: records.length, error: 'the log does not end at the expected head: records were removed or added' };
  }
  return {
    valid: true,
    count: records.length,
    ...(records.length || opts.anchor ? { head: { seq: prevSeq, hash: prevHash } } : {}),
    ...(signedThrough !== undefined ? { signedThrough } : {}),
    ...(key ? { unauthenticated: signedThrough === undefined ? records.length : prevSeq - signedThrough } : {}),
  };
}
