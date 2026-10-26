/**
 * Serves mandate status lists over HTTP and lets authorised operators revoke, suspend and reinstate entries.
 *
 *   GET  {publicPrefix}<list-id>                                   -> application/statuslist+jwt
 *   POST {adminPrefix}<list-id>/entries/<idx>/(revoke|suspend|reinstate)
 *   POST {adminPrefix}<list-id>/allocate                           -> a status reference for a new mandate
 *
 * The admin API has no default access rule: the integrator must supply `authorize`. Revocation is final;
 * a revoked entry cannot be reinstated or suspended, only a suspended one can.
 */
import type { SigningKey } from '../signer.js';
import { decodeJwt } from 'jose';
import { randomInt } from 'node:crypto';
import type { AuditLog } from '../audit.js';
import { sha256 } from '../encoding.js';
import { DEFAULT_STATUS_TTL_SECONDS, StatusListPublisher, STATUS_INVALID, STATUS_SUSPENDED, STATUS_VALID, type StatusReference } from '../status.js';
import { GATEWAY_PROBLEMS, problemFromSpec, problemResponse, type ProblemSpec } from './errors.js';

export type StatusValue = 'valid' | 'invalid' | 'suspended';
export type StatusOperation = 'revoke' | 'suspend' | 'reinstate';
export type SetStatusResult = 'ok' | 'unknown' | 'revoked';

const CODE: Record<StatusValue, 0 | 1 | 2> = { valid: STATUS_VALID as 0, invalid: STATUS_INVALID as 1, suspended: STATUS_SUSPENDED as 2 };
const OP_STATUS: Record<StatusOperation, StatusValue> = { revoke: 'invalid', suspend: 'suspended', reinstate: 'valid' };

/** Persistent state of one status list. Only non-valid entries are listed in `statuses`. */
export interface StatusListState {
  size: number;
  /** Increases on every change; lets a service tell whether its signed token is still current. */
  version: number;
  allocated: number[];
  statuses: Record<number, 1 | 2>;
}

/**
 * Storage for status lists, so the state survives restarts and can be shared by several service instances.
 * A database implementation must make `allocate` and `setStatus` atomic (a transaction or a conditional
 * update), and must keep "invalid is final" inside the same atomic step.
 */
export interface StatusListStore {
  /** Creates the list with `size` entries if it does not exist; returns its state. */
  init(listId: string, size: number): Promise<StatusListState>;
  get(listId: string): Promise<StatusListState | undefined>;
  /** Reserves a free index, chosen at random, and returns it. Throws when the list is full or unknown. */
  allocate(listId: string): Promise<number>;
  /** Sets an allocated entry. Returns `unknown` for an unknown list or entry, `revoked` when it is already invalid. */
  setStatus(listId: string, idx: number, status: 0 | 1 | 2): Promise<SetStatusResult>;
}

export class InMemoryStatusListStore implements StatusListStore {
  private readonly lists = new Map<string, { size: number; version: number; allocated: Set<number>; statuses: Map<number, 1 | 2> }>();

  async init(listId: string, size: number): Promise<StatusListState> {
    if (!Number.isSafeInteger(size) || size < 1) throw new Error('status list size must be a positive integer');
    if (!this.lists.has(listId)) this.lists.set(listId, { size, version: 0, allocated: new Set(), statuses: new Map() });
    return (await this.get(listId))!;
  }

  async get(listId: string): Promise<StatusListState | undefined> {
    const l = this.lists.get(listId);
    if (!l) return undefined;
    return { size: l.size, version: l.version, allocated: [...l.allocated], statuses: Object.fromEntries(l.statuses) };
  }

  async allocate(listId: string): Promise<number> {
    const l = this.lists.get(listId);
    if (!l) throw new Error('unknown status list');
    if (l.allocated.size >= l.size) throw new Error('status list is full');
    let idx: number;
    do idx = randomInt(l.size);
    while (l.allocated.has(idx));
    l.allocated.add(idx);
    return idx;
  }

  async setStatus(listId: string, idx: number, status: 0 | 1 | 2): Promise<SetStatusResult> {
    const l = this.lists.get(listId);
    if (!l || !l.allocated.has(idx)) return 'unknown';
    const current = l.statuses.get(idx) ?? 0;
    if (current === 1) return status === 1 ? 'ok' : 'revoked';
    if (current === status) return 'ok';
    if (status === 0) l.statuses.delete(idx);
    else l.statuses.set(idx, status);
    l.version++;
    return 'ok';
  }
}

/** What the service serves and administers. */
export interface StatusListSource {
  /** A signed status list token reflecting the current state. */
  token(now: number): Promise<string>;
  set(idx: number, status: StatusValue): Promise<SetStatusResult>;
  /** Present when the source can allocate entries for new mandates. */
  allocate?(): Promise<StatusReference>;
}

export interface ManagedStatusListOptions {
  id: string;
  /** The URL at which the list is served; mandates carry it and verifiers match it against the token `sub`. */
  uri: string;
  signingKey: SigningKey;
  store: StatusListStore;
  /** Number of entries. Default 16384. */
  size?: number;
  iss?: string;
  x5c?: string[];
  /** Token lifetime in seconds. Default 1 hour. */
  lifetimeSeconds?: number;
  /**
   * Cache hint for verifiers and HTTP caches, in seconds (the token `ttl`, and the bound on `Cache-Control`).
   * It is how long a revocation may go unnoticed by a verifier that caches. Default 60
   * (`DEFAULT_STATUS_TTL_SECONDS`); for payment tools, verifiers can also require a fresher list per call
   * with `maxStatusAgeSeconds`.
   */
  ttlSeconds?: number;
}

/**
 * A status list whose state lives in a StatusListStore. Tokens are signed with the library's
 * StatusListPublisher and re-signed when the state changes or the cached token is older than its ttl.
 */
export class ManagedStatusList implements StatusListSource {
  private cached?: { version: number; token: string; iat: number };
  private ready?: Promise<StatusListState>;

  constructor(private readonly opts: ManagedStatusListOptions) {
    if (!opts?.store || !opts.signingKey || typeof opts.uri !== 'string') throw new Error('ManagedStatusList needs id, uri, signingKey and store');
  }

  get id(): string {
    return this.opts.id;
  }

  get uri(): string {
    return this.opts.uri;
  }

  private init(): Promise<StatusListState> {
    this.ready ??= this.opts.store.init(this.opts.id, this.opts.size ?? 16384).catch((e) => {
      this.ready = undefined;
      throw e;
    });
    return this.ready;
  }

  async allocate(): Promise<StatusReference> {
    await this.init();
    const idx = await this.opts.store.allocate(this.opts.id);
    return { status_list: { uri: this.opts.uri, idx } };
  }

  async set(idx: number, status: StatusValue): Promise<SetStatusResult> {
    await this.init();
    return this.opts.store.setStatus(this.opts.id, idx, CODE[status]);
  }

  revoke(ref: StatusReference): Promise<SetStatusResult> {
    return this.set(this.indexOf(ref), 'invalid');
  }

  suspend(ref: StatusReference): Promise<SetStatusResult> {
    return this.set(this.indexOf(ref), 'suspended');
  }

  reinstate(ref: StatusReference): Promise<SetStatusResult> {
    return this.set(this.indexOf(ref), 'valid');
  }

  private indexOf(ref: StatusReference): number {
    if (ref?.status_list?.uri !== this.opts.uri) throw new Error('the reference belongs to another status list');
    return ref.status_list.idx;
  }

  async token(now = Math.floor(Date.now() / 1000)): Promise<string> {
    await this.init();
    const state = await this.opts.store.get(this.opts.id);
    if (!state) throw new Error('status list state is missing');
    const ttl = this.opts.ttlSeconds ?? DEFAULT_STATUS_TTL_SECONDS;
    const lifetime = this.opts.lifetimeSeconds ?? 3600;
    const c = this.cached;
    if (c && c.version === state.version && now >= c.iat && now < c.iat + Math.min(ttl, Math.floor(lifetime / 2))) return c.token;
    const publisher = new StatusListPublisher({
      uri: this.opts.uri,
      signingKey: this.opts.signingKey,
      size: state.size,
      lifetimeSeconds: lifetime,
      ttlSeconds: ttl,
      ...(this.opts.iss ? { iss: this.opts.iss } : {}),
      ...(this.opts.x5c ? { x5c: this.opts.x5c } : {}),
    });
    for (const [k, v] of Object.entries(state.statuses)) {
      const ref = { status_list: { uri: this.opts.uri, idx: Number(k) } };
      if (v === 1) publisher.revoke(ref);
      else if (v === 2) publisher.suspend(ref);
    }
    const token = await publisher.token(now);
    this.cached = { version: state.version, token, iat: now };
    return token;
  }
}

/**
 * Serves an in-memory StatusListPublisher. Its state is not persisted. The admin API acts only on entries
 * the publisher allocated, and a revoked entry stays revoked, whether it was revoked through the admin API
 * or directly on the publisher. Tokens are cached for `cacheSeconds` (default 5) and refreshed after every
 * change made through the adapter; changes made directly on the publisher show after at most that delay.
 */
export function publisherSource(publisher: StatusListPublisher, opts: { cacheSeconds?: number } = {}): StatusListSource {
  let cached: { token: string; iat: number } | undefined;
  const maxAge = opts.cacheSeconds ?? 5;
  return {
    async token(now) {
      if (cached && now >= cached.iat && now < cached.iat + maxAge) return cached.token;
      const token = await publisher.token(now);
      cached = { token, iat: now };
      return token;
    },
    async set(idx, status) {
      if (!Number.isSafeInteger(idx) || !publisher.isAllocated(idx)) return 'unknown';
      // The publisher is the source of truth: it may have been changed without this adapter.
      if (publisher.getStatus(idx) === STATUS_INVALID) return status === 'invalid' ? 'ok' : 'revoked';
      const ref = { status_list: { uri: publisher.uri, idx } };
      if (status === 'invalid') publisher.revoke(ref);
      else if (status === 'suspended') publisher.suspend(ref);
      else publisher.reinstate(ref);
      cached = undefined;
      return 'ok';
    },
    async allocate() {
      return publisher.allocate();
    },
  };
}

export type AdminOperation = { operation: StatusOperation; list: string; idx: number } | { operation: 'allocate'; list: string };

/**
 * Decides whether a caller may perform an admin operation. Return true, or `{ actor }` to record who acted.
 * Use credentials that a browser does not attach on its own (bearer tokens, mTLS), not cookies.
 */
export type AdminAuthorizer = (request: Request, op: AdminOperation) => boolean | { actor: string } | Promise<boolean | { actor: string }>;

export interface StatusServiceOptions {
  /** Status lists by id. Ids are 1 to 64 characters of `A-Z a-z 0-9 . _ -`. */
  lists: Record<string, StatusListSource>;
  /** Required: there is no default access rule for the admin API. */
  authorize: AdminAuthorizer;
  /** Default `/status/`. */
  publicPrefix?: string;
  /** Default `/admin/status/`. */
  adminPrefix?: string;
  /** Upper bound for `Cache-Control: max-age`, in seconds. Default 300. */
  maxCacheSeconds?: number;
  /** Records every admin operation. */
  audit?: AuditLog;
  onError?: (error: unknown, phase: string) => void;
  /** Clock in seconds, for tests. */
  now?: () => number;
}

export interface StatusService {
  /** Public and admin routes together. */
  handle(request: Request): Promise<Response>;
  /** Only `GET`/`HEAD` of status lists: what verifiers reach over the internet. */
  handlePublic(request: Request): Promise<Response>;
  /** Only the admin API: mount it on an internal listener when possible. */
  handleAdmin(request: Request): Promise<Response>;
}

const LIST_ID_RE = /^[A-Za-z0-9._-]{1,64}$/;
const IDX_RE = /^(0|[1-9][0-9]{0,9})$/;
export const STATUS_LIST_CONTENT_TYPE = 'application/statuslist+jwt';

function problem(spec: ProblemSpec, extra?: Record<string, string>): Response {
  const r = problemResponse(problemFromSpec(spec));
  for (const [k, v] of Object.entries(extra ?? {})) r.headers.set(k, v);
  return r;
}

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' },
  });
}

export function createStatusService(opts: StatusServiceOptions): StatusService {
  if (typeof opts?.authorize !== 'function') throw new Error('the status service needs an authorize function for its admin API');
  for (const id of Object.keys(opts.lists ?? {})) if (!LIST_ID_RE.test(id)) throw new Error(`status list id ${id} is not valid`);
  const lists = new Map(Object.entries(opts.lists ?? {}));
  const publicPrefix = opts.publicPrefix ?? '/status/';
  const adminPrefix = opts.adminPrefix ?? '/admin/status/';
  const maxCache = opts.maxCacheSeconds ?? 300;
  const now = opts.now ?? (() => Math.floor(Date.now() / 1000));
  const reportError = (e: unknown, phase: string) => {
    try {
      opts.onError?.(e, phase);
    } catch {
      // ignore
    }
  };

  async function servePublic(request: Request, url: URL): Promise<Response | undefined> {
    if (!url.pathname.startsWith(publicPrefix)) return undefined;
    const id = url.pathname.slice(publicPrefix.length);
    if (!LIST_ID_RE.test(id)) return undefined;
    const source = lists.get(id);
    if (!source) return problem(GATEWAY_PROBLEMS.entry_unknown);
    if (request.method !== 'GET' && request.method !== 'HEAD') return problem(GATEWAY_PROBLEMS.method_not_allowed, { allow: 'GET, HEAD' });
    const t = now();
    let token: string;
    let claims: ReturnType<typeof decodeJwt>;
    try {
      token = await source.token(t);
      claims = decodeJwt(token);
    } catch (e) {
      reportError(e, 'token');
      return problem(GATEWAY_PROBLEMS.processing_error);
    }
    const exp = typeof claims.exp === 'number' ? claims.exp : t;
    const ttl = typeof claims.ttl === 'number' && claims.ttl >= 0 ? claims.ttl : 0;
    // Shared caches must not keep the token longer than verifiers may (ttl) nor past its expiry.
    const maxAge = Math.max(0, Math.min(ttl, exp - t, maxCache));
    const etag = `"${sha256(token)}"`;
    const headers = new Headers({
      'content-type': STATUS_LIST_CONTENT_TYPE,
      'cache-control': `public, max-age=${maxAge}`,
      etag,
      'x-content-type-options': 'nosniff',
    });
    const inm = request.headers.get('if-none-match');
    if (inm && inm.split(',').some((v) => v.trim() === etag)) return new Response(null, { status: 304, headers });
    return new Response(request.method === 'HEAD' ? null : token, { status: 200, headers });
  }

  async function serveAdmin(request: Request, url: URL): Promise<Response | undefined> {
    if (!url.pathname.startsWith(adminPrefix)) return undefined;
    const parts = url.pathname.slice(adminPrefix.length).split('/');
    let op: AdminOperation;
    if (parts.length === 2 && parts[1] === 'allocate') op = { operation: 'allocate', list: parts[0] };
    else if (parts.length === 4 && parts[1] === 'entries' && IDX_RE.test(parts[2]) && Object.prototype.hasOwnProperty.call(OP_STATUS, parts[3])) {
      op = { operation: parts[3] as StatusOperation, list: parts[0], idx: Number(parts[2]) };
    } else return undefined;
    if (!LIST_ID_RE.test(op.list)) return undefined;
    if (request.method !== 'POST') return problem(GATEWAY_PROBLEMS.method_not_allowed, { allow: 'POST' });

    // Authorise before revealing whether the list or entry exists.
    let verdict: boolean | { actor: string };
    try {
      verdict = await opts.authorize(request, op);
    } catch (e) {
      reportError(e, 'authorize');
      return problem(GATEWAY_PROBLEMS.processing_error);
    }
    if (verdict !== true && !(typeof verdict === 'object' && verdict !== null && typeof verdict.actor === 'string')) {
      return problem(GATEWAY_PROBLEMS.admin_forbidden);
    }
    const actor = typeof verdict === 'object' ? verdict.actor : undefined;
    const source = lists.get(op.list);
    if (!source) return problem(GATEWAY_PROBLEMS.entry_unknown);

    const record = async (result: string) => {
      if (!opts.audit) return;
      await opts.audit.append({
        event: 'status_change',
        context: { list: op.list, operation: op.operation, ...('idx' in op ? { idx: op.idx } : {}), result, ...(actor ? { actor } : {}) },
      });
    };

    try {
      if (op.operation === 'allocate') {
        if (!source.allocate) return problem(GATEWAY_PROBLEMS.method_not_allowed);
        const ref = await source.allocate();
        await record('ok').catch((e) => reportError(e, 'audit'));
        return json(201, ref);
      }
      if (op.operation === 'reinstate' && opts.audit) {
        // Reinstating restores authority: it happens only once it is on record.
        try {
          await record('requested');
        } catch (e) {
          reportError(e, 'audit');
          return problem(GATEWAY_PROBLEMS.audit_unavailable);
        }
      }
      const result = await source.set(op.idx, OP_STATUS[op.operation]);
      await record(result).catch((e) => reportError(e, 'audit'));
      if (result === 'unknown') return problem(GATEWAY_PROBLEMS.entry_unknown);
      if (result === 'revoked') return problem(GATEWAY_PROBLEMS.entry_revoked);
      return json(200, { list: op.list, idx: op.idx, status: OP_STATUS[op.operation] });
    } catch (e) {
      reportError(e, op.operation);
      return problem(GATEWAY_PROBLEMS.processing_error);
    }
  }

  const route = async (request: Request, which: { pub: boolean; admin: boolean }): Promise<Response> => {
    let url: URL;
    try {
      url = new URL(request.url);
    } catch {
      return problem(GATEWAY_PROBLEMS.no_route);
    }
    const r = (which.admin ? await serveAdmin(request, url) : undefined) ?? (which.pub ? await servePublic(request, url) : undefined);
    return r ?? problem(GATEWAY_PROBLEMS.no_route);
  };

  return {
    handle: (r) => route(r, { pub: true, admin: true }),
    handlePublic: (r) => route(r, { pub: true, admin: false }),
    handleAdmin: (r) => route(r, { pub: false, admin: true }),
  };
}
