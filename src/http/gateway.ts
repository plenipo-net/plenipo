/**
 * A gateway that puts Plenipo in front of an HTTP API, built on the WHATWG Fetch API so it runs on Node,
 * Deno, Bun and edge runtimes. Adapters for Node `http` and Express-style middleware are in ./node.ts.
 *
 * For each request: match a route, decode the authorization headers, derive what the request actually does
 * (action, counterparty, amount, arguments) from the route mapping, and verify with `expected` set to that,
 * so the agent's signed invocation is bound to the real request.
 *
 * Settlement follows one rule: a reservation is released only when it is certain the action did not run.
 * A 2xx response commits; a 4xx response releases (a definite refusal, configurable); anything else (5xx,
 * a throw, a timeout, the client going away) leaves the reservation pending, to be reconciled or swept as
 * spent by the ledger. The downstream handler can state the outcome explicitly (see OUTCOME_HEADER).
 */
import type { SpendingLedger } from '../registry.js';
import { DEFAULT_MAX_REPLAY_BYTES, MAX_STORED_RESULT_BYTES, type AttemptOutcome, type IdempotencyStore } from '../idempotency.js';
import type { AuditLog } from '../audit.js';
import type { Amount, Decision } from '../types.js';
import { verifyAuthorization, type VerifyOptions } from '../verify.js';
import {
  GATEWAY_PROBLEMS,
  DENY_PROBLEMS,
  problemFromSpec,
  problemResponse,
  problemSpecForDecision,
  type ProblemDetails,
  type ProblemResponseOptions,
  type ProblemSpec,
} from './errors.js';
import { CHAIN_HEADER, INVOCATION_HEADER, parseAuthorizationHeaders, type HeaderLimits } from './transport.js';
import { pathProblem } from './target.js';

export type AllowDecision = Extract<Decision, { decision: 'ALLOW' }>;
export type DenyDecision = Extract<Decision, { decision: 'DENY' }>;

/**
 * Response header by which the protected API states what happened: `executed`, `not-executed` or `unknown`.
 * It overrides the status-code rule and is removed before the response reaches the client.
 */
export const OUTCOME_HEADER = 'plenipo-outcome';

/**
 * Response header set to `true` on the stored response of an earlier attempt with the same idempotency key,
 * returned instead of calling the API again.
 */
export const REPLAY_HEADER = 'plenipo-replay';

/** What a route mapping function sees. The body has already been read, within the size limit. */
export interface RouteContext {
  request: Request;
  url: URL;
  method: string;
  /** Raw (percent-encoded) path, as sent. */
  path: string;
  /** Path parameters, percent-decoded. */
  params: Record<string, string>;
  /** The request body bytes; empty when there is none. */
  body: Uint8Array;
  /**
   * The normalised JSON media type (`application/json` or `application/<x>+json`) when the body is
   * non-empty and declared as JSON; null otherwise.
   */
  mediaType: string | null;
  /** The body as UTF-8 text. Throws on invalid UTF-8. */
  text(): string;
  /**
   * The body as JSON, `null` when empty. Throws when it is not JSON, or when the request does not declare a
   * JSON media type (the gateway then answers 415): an API must never read the body differently.
   */
  json(): unknown;
}

type Extractor<T> = (ctx: RouteContext) => T | undefined | Promise<T | undefined>;

export interface GatewayRoute {
  /** HTTP method, e.g. `POST`. A `GET` route also covers `HEAD`, as most routers do. */
  method: string;
  /**
   * Path pattern: literal segments and `:name` parameters, e.g. `/accounts/:id/payments`. Matching is
   * case-insensitive on literal segments and accepts one trailing slash, as common routers do.
   */
  path: string;
  /** The concrete action this route performs, e.g. `payments.sepa.credit_transfer`. */
  action: string;
  /**
   * Reads the counterparty from the request, or `null` when this route has none. When a function returns
   * undefined the request is refused: an unbound counterparty would let an agent sign one and send another.
   * With `null`, an invocation that declares a counterparty is refused.
   */
  counterparty: Extractor<string> | null;
  /** Reads the amount from the request, or `null` when the route moves no money. Same rules as `counterparty`. */
  amount: Extractor<Amount> | null;
  /**
   * The arguments the invocation `args_hash` must cover. Default: `{ method, path, query, media_type, body }`
   * with the body parsed as JSON (see docs/integration.md). `null` disables argument binding: only do that
   * when the action, counterparty and amount fully determine the operation.
   */
  args?: Extractor<unknown> | null;
  /**
   * Maximum age of a cached status list for requests on this route, in seconds; overrides
   * `verify.maxStatusAgeSeconds`. Set it low on routes that move money, so a revoked mandate stops there
   * within this bound whatever the cache lifetime; `0` checks the list on every request.
   */
  maxStatusAgeSeconds?: number;
}

export interface GatewayRequestInfo {
  method: string;
  path: string;
  route?: GatewayRoute;
}

/** The protected API. `ctx` is absent only for unmatched requests forwarded with `unmatched: 'pass'`. */
export type Downstream = (
  request: Request,
  ctx?: { decision: AllowDecision; route: GatewayRoute; params: Record<string, string> },
) => Response | Promise<Response>;

/** Optional extra policy (OPA, Cedar, rules engine) evaluated after an ALLOW. Return false to refuse. */
export type PolicyHook = (decision: AllowDecision, ctx: RouteContext) => boolean | Promise<boolean>;

export type SettlementOutcome = 'commit' | 'release' | 'pending';

export interface GatewayEvent {
  phase: 'decision' | 'settlement';
  request: GatewayRequestInfo;
  decision?: Decision;
  problem?: ProblemDetails;
  settlement?: SettlementOutcome;
  status?: number;
}

export interface GatewayOptions extends HeaderLimits, ProblemResponseOptions {
  routes: GatewayRoute[];
  /** Verification options; `expected` is derived from each request and cannot be set here. */
  verify: Omit<VerifyOptions, 'expected'>;
  /** The protected API. Needed by `handle`; not by `authorize`. */
  downstream?: Downstream;
  /** Maximum request body read by the gateway, in bytes. Default 1 MiB. */
  maxBodyBytes?: number;
  /**
   * What to do with a request that matches no route. Default `deny` (404). `pass` forwards it unchecked,
   * except a request whose path matches or extends a protected route (in any letter case, with any method or
   * trailing slash): that one is always refused.
   */
  unmatched?: 'deny' | 'pass';
  /**
   * Outcome of a 4xx response from the API. Default `release`: a 4xx is a refusal, the action did not run.
   * Use `pending` when the API can answer 4xx after acting.
   */
  clientErrorOutcome?: 'release' | 'pending';
  /** Hash-chained audit log; every decision and settlement is appended. */
  audit?: AuditLog;
  /**
   * `deny` (default): refuse an allowed request when its decision cannot be recorded. `continue`: try a
   * minimal record, then proceed even if that fails too.
   */
  auditFailure?: 'deny' | 'continue';
  /** Called with every decision and settlement, for metrics and logs. Exceptions are ignored. */
  onEvent?: (e: GatewayEvent) => void;
  /** Called with internal errors (ledger, audit, downstream). Never sent to the client. */
  onError?: (error: unknown, phase: string) => void;
  policy?: PolicyHook;
  /** Forward the Plenipo headers to the downstream handler. Default false: they carry PID data. */
  forwardAuthorizationHeaders?: boolean;
  /**
   * Largest response kept for idempotent replays (`verify.idempotency`), in bytes of body. Default 65536,
   * at most `MAX_REPLAY_BODY_BYTES` (what a store accepts once encoded); `0` keeps none. Only requests that
   * carry an idempotency key are kept. A response that is larger, or whose body does not arrive within a
   * second, is passed through untouched and not kept: a retry then gets `already_executed` without it.
   * Kept responses live in the idempotency store with whatever personal data they carry.
   */
  maxReplayBytes?: number;
}

/**
 * How an allowed request ended. `status` applies the status rule (2xx commit, 4xx release by default,
 * otherwise pending); `error` is pending; `outcome` states it directly.
 */
export type SettleInput = { status: number } | { error: unknown } | { outcome: SettlementOutcome };

/** A response to keep for idempotent replays, as given to `settle` in authorize mode. */
export interface ReplayResponse {
  status: number;
  contentType?: string;
  body: Uint8Array | string;
}

/**
 * Largest body `maxReplayBytes` may allow: a stored response is base64 inside JSON, and a store accepts
 * `MAX_STORED_RESULT_BYTES` at most.
 */
export const MAX_REPLAY_BODY_BYTES = Math.floor(((MAX_STORED_RESULT_BYTES - 1024) * 3) / 4);

/** A response as stored for idempotent replays. */
interface StoredResponse {
  v: 1;
  status: number;
  content_type?: string;
  /** Base64 of the body bytes. */
  body: string;
}

export type AuthorizeResult =
  | { kind: 'deny'; response: Response; problem: ProblemDetails; decision?: Decision }
  | { kind: 'pass'; request: Request }
  | {
      kind: 'allow';
      decision: AllowDecision;
      route: GatewayRoute;
      params: Record<string, string>;
      /**
       * The request to hand to the API: same method, URL and body, a normalised Content-Type, without the
       * Plenipo headers by default, and without the client's abort signal (a client hanging up must not
       * cancel an action that may already be executing).
       */
      request: Request;
      /**
       * Settles the reservation and the idempotency key. `commit` and `release` are final; later calls are
       * ignored. `pending` records that the outcome is unknown and leaves both to reconciliation; a later
       * commit or release still applies. A reservation never settled stays pending and counts against the
       * limits, and its key blocks retries until reconciled. With `replay`, a committed request that carries
       * an idempotency key keeps that response for replays (body within `maxReplayBytes`).
       */
      settle(input: SettleInput, replay?: ReplayResponse): Promise<void>;
    };

export const DEFAULT_MAX_BODY_BYTES = 1024 * 1024;

const METHOD_RE = /^[A-Z]+$/;
const ACTION_RE = /^[a-z0-9_-]+(\.[a-z0-9_-]+)*$/;

type Segment = { literal: string } | { param: string };

interface CompiledRoute {
  route: GatewayRoute;
  method: string;
  segments: Segment[];
}

/** Lower-cased, percent-decoded form of a literal path segment; undecodable segments stay raw. */
function canonicalSegment(s: string): string {
  try {
    return decodeURIComponent(s).toLowerCase();
  } catch {
    return s.toLowerCase();
  }
}

function compileRoute(route: GatewayRoute): CompiledRoute {
  if (!route || typeof route !== 'object') throw new Error('route must be an object');
  const method = String(route.method).toUpperCase();
  if (!METHOD_RE.test(method)) throw new Error(`route method ${route.method} is not valid`);
  if (typeof route.path !== 'string' || !route.path.startsWith('/')) throw new Error(`route path ${route.path} must start with /`);
  if (typeof route.action !== 'string' || !ACTION_RE.test(route.action)) throw new Error(`route action ${route.action} must be a concrete action`);
  for (const k of ['counterparty', 'amount'] as const) {
    // Both must be stated: forgetting one would silently leave that field unbound to the request.
    if (!(k in route) || (route[k] !== null && typeof route[k] !== 'function')) {
      throw new Error(`route ${method} ${route.path} must set ${k} to a function or null`);
    }
  }
  if (route.args !== undefined && route.args !== null && typeof route.args !== 'function') throw new Error('route args must be a function or null');
  const age = route.maxStatusAgeSeconds;
  if (age !== undefined && (typeof age !== 'number' || !Number.isFinite(age) || age < 0)) throw new Error('route maxStatusAgeSeconds must be a non-negative number');
  const raw = route.path.length > 1 && route.path.endsWith('/') ? route.path.slice(0, -1) : route.path;
  const segments = raw
    .split('/')
    .slice(1)
    .map((s): Segment => {
      if (s.startsWith(':')) {
        if (!/^:[A-Za-z_][A-Za-z0-9_]*$/.test(s)) throw new Error(`route parameter ${s} is not valid`);
        return { param: s.slice(1) };
      }
      return { literal: canonicalSegment(s) };
    });
  return { route, method, segments };
}

/** Path segments of a request, without the leading empty one and without one trailing slash. */
function requestSegments(path: string): string[] {
  const parts = path.split('/').slice(1);
  if (parts.length > 1 && parts[parts.length - 1] === '') parts.pop();
  return parts;
}

function methodMatches(routeMethod: string, method: string): boolean {
  return routeMethod === method || (routeMethod === 'GET' && method === 'HEAD');
}

function matchRoute(routes: CompiledRoute[], method: string, path: string): { route: GatewayRoute; params: Record<string, string> } | undefined {
  const parts = requestSegments(path);
  for (const r of routes) {
    if (!methodMatches(r.method, method) || r.segments.length !== parts.length) continue;
    const params: Record<string, string> = {};
    let ok = true;
    for (let i = 0; i < parts.length && ok; i++) {
      const seg = r.segments[i];
      if ('literal' in seg) ok = seg.literal === canonicalSegment(parts[i]);
      else {
        try {
          const v = decodeURIComponent(parts[i]);
          // An empty or slash-bearing parameter would let one path name two resources.
          ok = v.length > 0 && !v.includes('/');
          params[seg.param] = v;
        } catch {
          ok = false;
        }
      }
    }
    if (ok) return { route: r.route, params };
  }
  return undefined;
}

/**
 * Whether a request path could reach a protected handler under some router: it equals or extends a route
 * pattern, ignoring method, letter case, empty segments and percent-encoding, with parameters matching any
 * non-empty segment. Deliberately broader than `matchRoute`.
 */
function touchesProtectedRoute(routes: CompiledRoute[], path: string): boolean {
  const parts = path.split('/').filter((s) => s.length > 0);
  return routes.some((r) => {
    const segs = r.segments.filter((s) => !('literal' in s) || s.literal.length > 0);
    if (segs.length === 0) return true;
    if (parts.length < segs.length) return false;
    return segs.every((s, i) => ('literal' in s ? s.literal === canonicalSegment(parts[i]) : parts[i].length > 0));
  });
}

class BodyTooLarge extends Error {}
class UnsupportedMediaType extends Error {}
class MalformedBody extends Error {}

/**
 * Whether a syntactically valid JSON text has an object with the same member name twice (after unescaping,
 * so `"a"` and `"\u0061"` are the same). JSON parsers disagree on which duplicate wins, so the gateway and
 * the API could read different values from the same bytes.
 */
export function hasDuplicateJsonKeys(text: string): boolean {
  const stack: Array<Set<string> | null> = [];
  let expectKey = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      // Meant for text that JSON.parse accepted; on anything else, fail instead of scanning past the end.
      if (j >= text.length) throw new Error('unterminated string in JSON text');
      const top = stack[stack.length - 1];
      if (expectKey && top) {
        const key = JSON.parse(text.slice(i, j + 1)) as string;
        if (top.has(key)) return true;
        top.add(key);
        expectKey = false;
      }
      i = j;
    } else if (c === '{') {
      stack.push(new Set());
      expectKey = true;
    } else if (c === '[') {
      stack.push(null);
      expectKey = false;
    } else if (c === '}' || c === ']') {
      stack.pop();
      expectKey = false;
    } else if (c === ',') {
      expectKey = stack[stack.length - 1] !== null && stack.length > 0;
    }
  }
  return false;
}

async function readBody(req: Request, max: number): Promise<Uint8Array> {
  if (!req.body) return new Uint8Array(0);
  const declared = Number(req.headers.get('content-length') ?? '0');
  if (declared > max) throw new BodyTooLarge();
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > max) {
      await reader.cancel().catch(() => undefined);
      throw new BodyTooLarge();
    }
    chunks.push(value);
  }
  const out = new Uint8Array(size);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.byteLength;
  }
  return out;
}

/**
 * Parses a Content-Type as a JSON media type: `application/json` or `application/<x>+json`, optionally with
 * `charset=utf-8`. Returns the lower-cased type, or null for anything else (including several values).
 */
export function jsonMediaType(contentType: string | null): string | null {
  if (!contentType) return null;
  const [type, ...params] = contentType.split(';').map((s) => s.trim());
  const t = type.toLowerCase();
  if (!/^application\/([a-z0-9!#$&^_.-]+\+)?json$/.test(t)) return null;
  for (const p of params) {
    const m = /^charset\s*=\s*"?([^"]*)"?$/i.exec(p);
    if (!m || m[1].toLowerCase() !== 'utf-8') return null;
  }
  return t;
}

function makeContext(request: Request, url: URL, params: Record<string, string>, body: Uint8Array): RouteContext {
  let text: string | undefined;
  let json: { v: unknown } | undefined;
  const encoding = (request.headers.get('content-encoding') ?? 'identity').trim().toLowerCase();
  const mediaType = body.byteLength > 0 && encoding === 'identity' ? jsonMediaType(request.headers.get('content-type')) : null;
  const ctx: RouteContext = {
    request,
    url,
    method: request.method.toUpperCase(),
    path: url.pathname,
    params,
    body,
    mediaType,
    text() {
      text ??= new TextDecoder('utf-8', { fatal: true }).decode(body);
      return text;
    },
    json() {
      if (!json) {
        if (body.byteLength === 0) json = { v: null };
        else {
          // The API will parse the body by its Content-Type; reading it as JSON under any other type would
          // bind the invocation to fields the API never sees, and let it execute fields nobody signed.
          if (!mediaType) throw new UnsupportedMediaType('the body is not declared as JSON');
          let text: string;
          let v: unknown;
          try {
            text = ctx.text();
            v = JSON.parse(text);
          } catch {
            throw new MalformedBody('the body is not valid UTF-8 JSON');
          }
          if (hasDuplicateJsonKeys(text)) throw new MalformedBody('the body has an object with a duplicate member name');
          json = { v };
        }
      }
      return json.v;
    },
  };
  return ctx;
}

/** Query parameters as a record; a repeated name becomes an array, in order. */
function queryRecord(url: URL): Record<string, string | string[]> {
  const out: Record<string, string | string[]> = {};
  for (const [k, v] of url.searchParams) {
    const cur = out[k];
    if (cur === undefined) out[k] = v;
    else out[k] = Array.isArray(cur) ? [...cur, v] : [cur, v];
  }
  return out;
}

/** The default `args` of a route: what the agent hashes into `args_hash`. */
export function defaultRequestArgs(ctx: RouteContext): unknown {
  const body = ctx.json();
  return { method: ctx.method, path: ctx.path, query: queryRecord(ctx.url), media_type: ctx.mediaType, body };
}

class Unmapped extends Error {}

function validExpectedAmount(a: unknown): a is Amount {
  if (typeof a !== 'object' || a === null) return false;
  const x = a as Record<string, unknown>;
  return typeof x.value === 'number' && Number.isSafeInteger(x.value) && x.value >= 0 && typeof x.currency === 'string' && /^[A-Z]{3}$/.test(x.currency);
}

async function deriveExpected(route: GatewayRoute, ctx: RouteContext): Promise<NonNullable<VerifyOptions['expected']>> {
  const expected: NonNullable<VerifyOptions['expected']> = { action: route.action };
  try {
    // `null` tells the verifier that the call has no counterparty / moves no money: the invocation must not
    // declare one, and counterparty restrictions and spending limits do not apply (no reservation).
    if (route.counterparty === null) expected.counterparty = null;
    if (route.amount === null) expected.amount = null;
    if (route.counterparty) {
      const c = await route.counterparty(ctx);
      if (typeof c !== 'string' || c.length === 0) throw new Unmapped('the route could not read the counterparty');
      expected.counterparty = c;
    }
    if (route.amount) {
      const a = await route.amount(ctx);
      if (!validExpectedAmount(a)) throw new Unmapped('the route could not read a valid amount');
      expected.amount = { value: a.value, currency: a.currency };
    }
    if (route.args !== null) {
      const args = await (route.args ?? defaultRequestArgs)(ctx);
      if (args === undefined) throw new Unmapped('the route could not read the arguments');
      expected.args = args;
    }
  } catch (e) {
    if (e instanceof Unmapped || e instanceof UnsupportedMediaType || e instanceof MalformedBody) throw e;
    throw new Unmapped(`route mapping failed: ${(e as Error)?.message ?? String(e)}`);
  }
  return expected;
}

function forwardRequest(req: Request, ctx: RouteContext, keepAuth: boolean): Request {
  const headers = new Headers(req.headers);
  if (!keepAuth) {
    headers.delete(CHAIN_HEADER);
    headers.delete(INVOCATION_HEADER);
  }
  // Only the API may state an outcome; a client-supplied one must not reach it looking like its own.
  headers.delete(OUTCOME_HEADER);
  // A JSON body goes out with exactly one, normalised JSON Content-Type, so the API parses what was checked.
  if (ctx.mediaType) headers.set('content-type', ctx.mediaType);
  const hasBody = ctx.body.byteLength > 0 && req.method !== 'GET' && req.method !== 'HEAD';
  // No `signal`: the client's abort must not cancel the API call, whose outcome would then be unknown.
  return new Request(ctx.url, { method: req.method, headers, body: hasBody ? (ctx.body as Uint8Array<ArrayBuffer>) : undefined });
}

/** Maps an OUTCOME_HEADER value to a settlement outcome; undefined for absent or unknown values. */
export function outcomeFromHeader(value: string | null): SettlementOutcome | undefined {
  switch (value?.trim().toLowerCase()) {
    case 'executed':
      return 'commit';
    case 'not-executed':
      return 'release';
    case 'unknown':
      return 'pending';
    default:
      return undefined;
  }
}

/**
 * Reads the body of a response to keep it for replays, up to `max` bytes and one second. No tee: the body is
 * read once, and the response handed back to the client is rebuilt from the bytes read so far followed by the
 * rest of the stream, so a large or never-ending body reaches the client as it would have without capture.
 */
async function captureResponse(response: Response, max: number): Promise<{ response: Response; replay?: ReplayResponse }> {
  const contentType = response.headers.get('content-type') ?? undefined;
  const replayOf = (body: Uint8Array): ReplayResponse => ({ status: response.status, ...(contentType ? { contentType } : {}), body });
  if (!response.body) return { response, replay: replayOf(new Uint8Array(0)) };
  if (Number(response.headers.get('content-length') ?? '0') > max) return { response };
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  let pending: Promise<ReadableStreamReadResult<Uint8Array>> | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<'timeout'>((r) => {
    timer = setTimeout(() => r('timeout'), 1000);
  });
  const rebuild = (complete: boolean): Response => {
    const prefix = chunks.slice();
    const stream = new ReadableStream<Uint8Array>({
      start(c) {
        for (const chunk of prefix) c.enqueue(chunk);
        if (complete) c.close();
      },
      async pull(c) {
        // A read started during capture and still pending comes first, or its bytes would be lost.
        const next = await (pending ?? reader.read());
        pending = undefined;
        if (next.done) c.close();
        else c.enqueue(next.value);
      },
      cancel(reason) {
        return reader.cancel(reason);
      },
    });
    return new Response(stream, { status: response.status, statusText: response.statusText, headers: response.headers });
  };
  try {
    for (;;) {
      pending = reader.read();
      const next = await Promise.race([pending, timeout]);
      if (next === 'timeout') return { response: rebuild(false) };
      pending = undefined;
      if (next.done) {
        const body = new Uint8Array(size);
        let off = 0;
        for (const c of chunks) {
          body.set(c, off);
          off += c.byteLength;
        }
        return { response: rebuild(true), replay: replayOf(body) };
      }
      chunks.push(next.value);
      size += next.value.byteLength;
      if (size > max) return { response: rebuild(false) };
    }
  } catch {
    // The body failed while being read: hand the client what arrived, then the same failure.
    pending = Promise.reject(new Error('the response body could not be read'));
    pending.catch(() => undefined);
    return { response: rebuild(false) };
  } finally {
    clearTimeout(timer);
  }
}

/** The stored response of an earlier attempt, or undefined when none was kept or it cannot be read. */
function replayResponse(result: string | undefined): Response | undefined {
  if (result === undefined) return undefined;
  try {
    const r = JSON.parse(result) as StoredResponse;
    if (r?.v !== 1 || !Number.isInteger(r.status) || r.status < 200 || r.status > 599 || typeof r.body !== 'string') return undefined;
    const headers = new Headers({ 'cache-control': 'no-store', [REPLAY_HEADER]: 'true' });
    if (typeof r.content_type === 'string' && /^[\x20-\x7e]+$/.test(r.content_type)) headers.set('content-type', r.content_type);
    const body = Buffer.from(r.body, 'base64');
    return new Response(r.status === 204 || r.status === 205 || r.status === 304 ? null : body, { status: r.status, headers });
  } catch {
    return undefined;
  }
}

const ATTEMPT_OUTCOME: Record<SettlementOutcome, AttemptOutcome> = { commit: 'executed', release: 'not_executed', pending: 'unknown' };

export interface Gateway {
  /** Verifies a request and, on ALLOW, returns a settle function instead of calling the downstream handler. */
  authorize(request: Request): Promise<AuthorizeResult>;
  /** Fetch-style handler: authorizes, calls `downstream`, settles, and returns its response or a problem. */
  handle(request: Request): Promise<Response>;
  /** Applies the status-code rule of this gateway: 2xx commit, 4xx `clientErrorOutcome`, otherwise pending. */
  outcomeForStatus(status: number): SettlementOutcome;
}

export function createGateway(opts: GatewayOptions): Gateway {
  if (!opts?.verify) throw new Error('gateway needs verify options');
  if (!Array.isArray(opts.routes) || opts.routes.length === 0) throw new Error('gateway needs at least one route');
  if ('expected' in (opts.verify as Record<string, unknown>)) throw new Error('verify.expected is derived from each request; do not set it');
  const routes = opts.routes.map(compileRoute);
  const maxBody = opts.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
  const ledger: SpendingLedger | undefined = opts.verify.ledger;
  const idempotency: IdempotencyStore | undefined = opts.verify.idempotency;
  const maxReplay = opts.maxReplayBytes ?? DEFAULT_MAX_REPLAY_BYTES;
  if (!Number.isSafeInteger(maxReplay) || maxReplay < 0 || maxReplay > MAX_REPLAY_BODY_BYTES) {
    throw new Error(`maxReplayBytes must be an integer from 0 to ${MAX_REPLAY_BODY_BYTES}, what a store accepts once encoded`);
  }

  const safe = (fn: () => void) => {
    try {
      fn();
    } catch {
      // Observability callbacks must not change the outcome.
    }
  };
  const reportError = (e: unknown, phase: string) => safe(() => opts.onError?.(e, phase));
  const emit = (e: GatewayEvent) => safe(() => opts.onEvent?.(e));

  function outcomeForStatus(status: number): SettlementOutcome {
    if (!Number.isInteger(status)) return 'pending';
    if (status >= 200 && status < 300) return 'commit';
    if (status >= 400 && status < 500) return opts.clientErrorOutcome ?? 'release';
    return 'pending';
  }

  async function deny(
    info: GatewayRequestInfo,
    spec: ProblemSpec,
    audit: { decision?: Decision; reason?: string; invocation?: string; mandateIds?: string[] },
    at?: number,
  ): Promise<AuthorizeResult> {
    const problem = problemFromSpec(spec, at);
    if (opts.audit && info.route) {
      try {
        await opts.audit.recordDecision({
          decision: audit.decision,
          problem: problem.code,
          reason: audit.reason,
          invocation: audit.invocation,
          mandateIds: audit.mandateIds,
          http: { method: info.method, path: info.path, status: problem.status },
        });
      } catch (e) {
        reportError(e, 'audit');
      }
    }
    emit({ phase: 'decision', request: info, decision: audit.decision, problem });
    return { kind: 'deny', response: problemResponse(problem, opts), problem, decision: audit.decision };
  }

  /** Ends the attempt holding the idempotency key. A store that fails leaves the key blocked: safe side. */
  async function finishAttempt(decision: AllowDecision, outcome: AttemptOutcome, result?: string): Promise<void> {
    if (!decision.idempotency || !idempotency) return;
    const { key, attempt } = decision.idempotency;
    try {
      await idempotency.finish(key, attempt, outcome, result);
    } catch (e) {
      reportError(e, 'idempotency');
      // A store that refuses the response must still learn that the request ran.
      if (result !== undefined) await idempotency.finish(key, attempt, outcome).catch((e2) => reportError(e2, 'idempotency'));
    }
  }

  /** The stored form of a response to keep, or undefined when it is too large or not a usable status. */
  function storedReplay(replay: ReplayResponse | undefined): string | undefined {
    if (!replay || maxReplay <= 0) return undefined;
    const body = typeof replay.body === 'string' ? new TextEncoder().encode(replay.body) : replay.body;
    if (!(body instanceof Uint8Array) || body.byteLength > maxReplay || !Number.isInteger(replay.status)) return undefined;
    const stored: StoredResponse = {
      v: 1,
      status: replay.status,
      ...(typeof replay.contentType === 'string' ? { content_type: replay.contentType } : {}),
      body: Buffer.from(body.buffer, body.byteOffset, body.byteLength).toString('base64'),
    };
    return JSON.stringify(stored);
  }

  async function settleReservation(reservation: string | undefined, outcome: 'commit' | 'release'): Promise<void> {
    if (!reservation || !ledger) return;
    try {
      if (outcome === 'commit') await ledger.commit(reservation);
      else await ledger.release(reservation);
    } catch (e) {
      // A reservation that cannot be settled stays pending and keeps counting against the limits: safe side.
      reportError(e, outcome);
    }
  }

  async function authorize(request: Request): Promise<AuthorizeResult> {
    let url: URL;
    try {
      url = new URL(request.url);
    } catch {
      return deny({ method: request.method, path: '' }, GATEWAY_PROBLEMS.no_route, {});
    }
    const method = request.method.toUpperCase();
    // Encoded slashes, backslashes and controls let routers disagree on segments and parameters: refuse them,
    // also for paths that would otherwise be passed through.
    if (pathProblem(url.pathname)) {
      return deny({ method, path: url.pathname, route: matchRoute(routes, method, url.pathname)?.route }, GATEWAY_PROBLEMS.malformed_target, { reason: 'the request target is ambiguous' });
    }
    const matched = matchRoute(routes, method, url.pathname);
    const info: GatewayRequestInfo = { method, path: url.pathname, route: matched?.route };
    if (!matched) {
      // Pass only what no router could take for a protected route.
      if (opts.unmatched === 'pass' && !touchesProtectedRoute(routes, url.pathname)) return { kind: 'pass', request };
      return deny(info, GATEWAY_PROBLEMS.no_route, {});
    }
    const { route, params } = matched;

    const parsed = parseAuthorizationHeaders(request.headers, opts);
    if (!parsed.ok) return deny(info, parsed.problem, { reason: parsed.reason });

    let body: Uint8Array;
    try {
      body = await readBody(request, maxBody);
    } catch (e) {
      if (e instanceof BodyTooLarge) return deny(info, GATEWAY_PROBLEMS.body_too_large, { reason: 'body too large', invocation: parsed.invocation });
      return deny(info, GATEWAY_PROBLEMS.malformed_authorization, { reason: 'body could not be read', invocation: parsed.invocation });
    }
    const ctx = makeContext(request, url, params, body);

    let expected: NonNullable<VerifyOptions['expected']>;
    try {
      expected = await deriveExpected(route, ctx);
    } catch (e) {
      if (e instanceof UnsupportedMediaType) {
        return deny(info, GATEWAY_PROBLEMS.unsupported_media_type, { reason: e.message, invocation: parsed.invocation });
      }
      if (e instanceof MalformedBody) return deny(info, GATEWAY_PROBLEMS.malformed_body, { reason: e.message, invocation: parsed.invocation });
      return deny(info, GATEWAY_PROBLEMS.request_unmapped, { reason: (e as Error).message, invocation: parsed.invocation });
    }

    let decision: Decision;
    try {
      decision = await verifyAuthorization(parsed.chain, parsed.invocation, {
        ...opts.verify,
        ...(route.maxStatusAgeSeconds !== undefined ? { maxStatusAgeSeconds: route.maxStatusAgeSeconds } : {}),
        expected,
      });
    } catch (e) {
      // verifyAuthorization does not throw by contract; if it ever does, refuse without detail.
      reportError(e, 'verify');
      return deny(info, GATEWAY_PROBLEMS.processing_error, { reason: 'verifier threw', invocation: parsed.invocation });
    }
    if (decision.decision === 'DENY') {
      const denied = await deny(info, problemSpecForDecision(decision), { decision, invocation: parsed.invocation }, decision.at);
      // A retry of a request that already ran gets that request's stored response, and the API is not called.
      if (decision.code === 'ALREADY_EXECUTED' && denied.kind === 'deny') {
        const replay = replayResponse(decision.replay?.result);
        if (replay) return { ...denied, response: replay };
      }
      return denied;
    }

    // From here on an ALLOW holds a reservation. Until the API is called, the action certainly has not run,
    // so every refusal below releases it; after that, settle() decides.
    const allowed = decision;
    const release = async () => {
      await settleReservation(allowed.reservation, 'release');
      await finishAttempt(allowed, 'not_executed');
    };

    // A route without a counterparty or amount must not run an invocation that names one: the mandate would
    // have been checked against a value the request does not carry.
    if ((route.counterparty === null && allowed.invocation.counterparty !== undefined) || (route.amount === null && allowed.invocation.amount !== undefined)) {
      await release();
      return deny(info, DENY_PROBLEMS.INVOCATION_MISMATCH, {
        reason: 'invocation declares a counterparty or amount that this route does not carry',
        invocation: parsed.invocation,
        mandateIds: allowed.path.map((p) => p.mandate_id),
      });
    }

    if (opts.policy) {
      let ok = false;
      try {
        ok = (await opts.policy(allowed, ctx)) === true;
      } catch (e) {
        reportError(e, 'policy');
      }
      if (!ok) {
        await release();
        return deny(info, GATEWAY_PROBLEMS.policy_denied, {
          reason: 'refused by the service policy',
          invocation: parsed.invocation,
          mandateIds: allowed.path.map((p) => p.mandate_id),
        });
      }
    }

    if (opts.audit) {
      try {
        await opts.audit.recordDecision({
          decision: allowed,
          invocation: parsed.invocation,
          chain: parsed.chain,
          http: { method, path: url.pathname },
        });
      } catch (e) {
        reportError(e, 'audit');
        if ((opts.auditFailure ?? 'deny') === 'deny') {
          await release();
          const problem = problemFromSpec(GATEWAY_PROBLEMS.audit_unavailable);
          emit({ phase: 'decision', request: info, decision: allowed, problem });
          return { kind: 'deny', response: problemResponse(problem, opts), problem, decision: allowed };
        }
        // `continue`: never proceed without at least trying a record that names the decision.
        try {
          await opts.audit.append({
            event: 'decision',
            decision: 'ALLOW',
            reason: 'full decision record failed',
            mandate_ids: allowed.path.map((p) => p.mandate_id),
            reservation: allowed.reservation,
            http: { method, path: url.pathname },
          });
        } catch (e2) {
          reportError(e2, 'audit');
        }
      }
    }
    emit({ phase: 'decision', request: info, decision: allowed });

    let final = false;
    const settle = async (input: SettleInput, replay?: ReplayResponse): Promise<void> => {
      if (final) return;
      let outcome: SettlementOutcome;
      let status: number | undefined;
      if ('outcome' in input) outcome = input.outcome === 'commit' || input.outcome === 'release' ? input.outcome : 'pending';
      else if ('status' in input) {
        status = input.status;
        outcome = outcomeForStatus(status);
      } else outcome = 'pending';
      if (outcome !== 'pending') final = true;
      await finishAttempt(allowed, ATTEMPT_OUTCOME[outcome], outcome === 'commit' ? storedReplay(replay) : undefined);
      if (outcome !== 'pending') await settleReservation(allowed.reservation, outcome);
      if (opts.audit) {
        try {
          await opts.audit.recordSettlement({
            reservation: allowed.reservation,
            settlement: outcome,
            invocation: parsed.invocation,
            http: { method, path: url.pathname, ...(status !== undefined ? { status } : {}) },
            ...('error' in input ? { reason: 'downstream handler failed; outcome unknown' } : {}),
          });
        } catch (e) {
          reportError(e, 'audit');
        }
      }
      emit({ phase: 'settlement', request: info, decision: allowed, settlement: outcome, status });
    };

    return {
      kind: 'allow',
      decision: allowed,
      route,
      params,
      request: forwardRequest(request, ctx, opts.forwardAuthorizationHeaders ?? false),
      settle,
    };
  }

  async function handle(request: Request): Promise<Response> {
    const downstream = opts.downstream;
    if (!downstream) throw new Error('gateway.handle needs a downstream handler');
    let result: AuthorizeResult;
    try {
      result = await authorize(request);
    } catch (e) {
      reportError(e, 'authorize');
      return problemResponse(problemFromSpec(GATEWAY_PROBLEMS.processing_error), opts);
    }
    if (result.kind === 'deny') return result.response;
    if (result.kind === 'pass') return downstream(result.request);
    let response: Response;
    try {
      response = await downstream(result.request, { decision: result.decision, route: result.route, params: result.params });
      if (!(response instanceof Response)) throw new TypeError('downstream did not return a Response');
    } catch (e) {
      // The API may have acted before failing: the outcome is unknown, so the reservation stays pending.
      await result.settle({ error: e });
      reportError(e, 'downstream');
      return problemResponse(problemFromSpec(GATEWAY_PROBLEMS.processing_error), opts);
    }
    const explicit = outcomeFromHeader(response.headers.get(OUTCOME_HEADER));
    if (response.headers.has(OUTCOME_HEADER)) {
      const headers = new Headers(response.headers);
      headers.delete(OUTCOME_HEADER);
      response = new Response(response.body, { status: response.status, statusText: response.statusText, headers });
    }
    const input: SettleInput = explicit ? { outcome: explicit } : { status: response.status };
    // Only a request whose key the store keeps, and that committed, is worth reading the body of.
    let replay: ReplayResponse | undefined;
    const commits = explicit ? explicit === 'commit' : outcomeForStatus(response.status) === 'commit';
    if (commits && result.decision.idempotency && idempotency && maxReplay > 0) {
      const captured = await captureResponse(response, maxReplay);
      response = captured.response;
      replay = captured.replay;
    }
    await result.settle(input, replay);
    return response;
  }

  return { authorize, handle, outcomeForStatus };
}
