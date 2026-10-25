/**
 * Adapters from the Fetch-style gateway and status service to Node `http` and Express-style middleware.
 * Express is typed structurally: there is no dependency on it.
 */
import type { IncomingMessage, ServerResponse } from 'node:http';
import { GATEWAY_PROBLEMS, problemFromSpec, problemResponse } from './errors.js';
import type { AllowDecision, Gateway, GatewayOptions, GatewayRoute } from './gateway.js';
import { createGateway, DEFAULT_MAX_BODY_BYTES, jsonMediaType, OUTCOME_HEADER } from './gateway.js';
import { pathProblem, TargetError, urlFromRawTarget } from './target.js';
import { CHAIN_HEADER, INVOCATION_HEADER } from './transport.js';

export interface NodeAdapterOptions {
  /**
   * Origin used to build request URLs, e.g. `https://api.bank.example`. The Host header is not trusted for
   * this. Default `http://localhost`.
   */
  origin?: string;
  /** Maximum request body read by the adapter. Default 1 MiB. */
  maxBodyBytes?: number;
  /** Called when the handler or the socket fails. */
  onError?: (error: unknown) => void;
}

class TooLarge extends Error {}

function readNodeBody(req: IncomingMessage, max: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const declared = Number(req.headers['content-length'] ?? '0');
    if (declared > max) {
      reject(new TooLarge());
      return;
    }
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (c: Buffer) => {
      size += c.length;
      if (size > max) {
        req.removeAllListeners('data');
        req.resume();
        reject(new TooLarge());
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

/**
 * Refuses what the gateway cannot check exactly as the router will route it: a request target that URL
 * parsing would change (see target.ts), and a body on GET or HEAD, which the checked Request drops but a
 * body parser would still hand to the handler. Returns the problem to answer with, or undefined.
 */
function requestLineProblem(req: IncomingMessage, target: string | undefined): keyof typeof GATEWAY_PROBLEMS | undefined {
  const t = target ?? '/';
  const q = t.indexOf('?');
  if (pathProblem(q < 0 ? t : t.slice(0, q))) return 'malformed_target';
  const method = (req.method ?? 'GET').toUpperCase();
  if ((method === 'GET' || method === 'HEAD') && hasBody(req)) return 'body_not_allowed';
  return undefined;
}

function toHeaders(req: IncomingMessage): Headers {
  const h = new Headers();
  const raw = req.rawHeaders;
  for (let i = 0; i + 1 < raw.length; i += 2) {
    try {
      h.append(raw[i], raw[i + 1]);
    } catch {
      // A header the Fetch API refuses (invalid characters) is dropped rather than failing the request.
    }
  }
  return h;
}

/** Builds a Fetch Request from a Node request whose body is already in memory. */
export function toFetchRequest(req: IncomingMessage, body: Uint8Array | undefined, origin = 'http://localhost', path?: string): Request {
  const method = (req.method ?? 'GET').toUpperCase();
  const hasBody = body && body.byteLength > 0 && method !== 'GET' && method !== 'HEAD';
  // Throws TargetError for a target the router could read differently from the URL checked here.
  return new Request(urlFromRawTarget(path ?? req.url, origin), {
    method,
    headers: toHeaders(req),
    body: hasBody ? (body as Uint8Array<ArrayBuffer>) : undefined,
  });
}

/** Writes a Fetch Response to a Node response. The body is buffered. */
export async function writeFetchResponse(res: ServerResponse, response: Response, method = 'GET'): Promise<void> {
  const headers: Record<string, string | string[]> = {};
  response.headers.forEach((v, k) => {
    if (k !== 'set-cookie') headers[k] = v;
  });
  const cookies = response.headers.getSetCookie();
  if (cookies.length) headers['set-cookie'] = cookies;
  const body = method === 'HEAD' || response.status === 204 || response.status === 304 ? undefined : Buffer.from(await response.arrayBuffer());
  res.writeHead(response.status, headers);
  res.end(body);
}

/** Turns a Fetch-style handler (`gateway.handle`, `statusService.handle`) into a Node `http` request listener. */
export function toNodeListener(
  handler: (request: Request) => Promise<Response>,
  opts: NodeAdapterOptions = {},
): (req: IncomingMessage, res: ServerResponse) => void {
  const origin = opts.origin ?? 'http://localhost';
  const max = opts.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
  return (req, res) => {
    void (async () => {
      let response: Response;
      try {
        const refused = requestLineProblem(req, req.url);
        if (refused) {
          req.resume();
          response = problemResponse(problemFromSpec(GATEWAY_PROBLEMS[refused]));
        } else {
          const body = await readNodeBody(req, max);
          response = await handler(toFetchRequest(req, body, origin));
        }
      } catch (e) {
        if (e instanceof TooLarge) response = problemResponse(problemFromSpec(GATEWAY_PROBLEMS.body_too_large));
        else if (e instanceof TargetError) response = problemResponse(problemFromSpec(GATEWAY_PROBLEMS.malformed_target));
        else {
          opts.onError?.(e);
          response = problemResponse(problemFromSpec(GATEWAY_PROBLEMS.processing_error));
        }
      }
      await writeFetchResponse(res, response, req.method);
    })().catch((e) => {
      opts.onError?.(e);
      if (!res.headersSent) res.writeHead(500);
      res.end();
    });
  };
}

/** What the middleware puts on `req.plenipo` for an allowed request. */
export interface PlenipoRequestContext {
  decision: AllowDecision;
  route: GatewayRoute;
  params: Record<string, string>;
  /**
   * States what happened to the action: `executed` commits the reservation, `not-executed` releases it,
   * `unknown` leaves it pending for reconciliation. Once called, the response status no longer decides.
   * Without it, the status of the finished response decides (2xx commit, 4xx release, otherwise pending).
   */
  settle(outcome: 'executed' | 'not-executed' | 'unknown'): Promise<void>;
}

/** The subset of an Express request the middleware uses. */
export interface ExpressLikeRequest extends IncomingMessage {
  originalUrl?: string;
  /** Set by a body parser mounted before the middleware, or by the middleware itself. */
  body?: unknown;
  /** body-parser 1.x marks a consumed body with this flag. */
  _body?: boolean;
  /** Set by the middleware on ALLOW. */
  plenipo?: PlenipoRequestContext;
}
export type ExpressLikeNext = (err?: unknown) => void;
export type ExpressLikeMiddleware = (req: ExpressLikeRequest, res: ServerResponse, next: ExpressLikeNext) => void;

function hasBody(req: IncomingMessage): boolean {
  const len = Number(req.headers['content-length'] ?? '0');
  return len > 0 || req.headers['transfer-encoding'] !== undefined;
}

// The Plenipo headers carry PID data; a client-supplied Plenipo-Outcome must never look like the API's own.
const AUTH_HEADERS = new Set([CHAIN_HEADER, INVOCATION_HEADER, OUTCOME_HEADER]);

/** Removes the PID-bearing Plenipo headers from a Node request, so handlers and their loggers never see them. */
function stripAuthorizationHeaders(req: IncomingMessage): void {
  for (const h of AUTH_HEADERS) delete req.headers[h];
  const raw = req.rawHeaders;
  for (let i = raw.length - 2; i >= 0; i -= 2) if (AUTH_HEADERS.has(raw[i].toLowerCase())) raw.splice(i, 2);
}

class Refused extends Error {
  constructor(readonly problem: keyof typeof GATEWAY_PROBLEMS) {
    super(problem);
  }
}

/**
 * The exact body bytes the handlers will act on. The middleware reads the stream itself whenever it is still
 * unread, whatever `req.body` says: body-parser 1.x sets `req.body = {}` for a type it does not handle and
 * leaves the stream to a later parser, which would then execute fields nobody checked. A stream already
 * consumed is accepted only when a JSON parser consumed it.
 */
async function bodyFor(req: ExpressLikeRequest, max: number): Promise<Uint8Array | undefined> {
  if (!hasBody(req)) return undefined;
  if (!req.readableEnded && !req._body) {
    let raw: Buffer;
    try {
      raw = await readNodeBody(req, max);
    } catch (e) {
      if (e instanceof TooLarge) throw new Refused('body_too_large');
      throw e;
    }
    // Later parsers skip a consumed stream: body-parser 2.x sees it finished, 1.x sees the flag.
    req._body = true;
    if (jsonMediaType(headerValue(req.headers['content-type']))) {
      try {
        req.body = JSON.parse(raw.toString('utf8'));
      } catch {
        req.body = raw;
      }
    } else req.body = raw;
    return raw;
  }
  if (req.body !== undefined && jsonMediaType(headerValue(req.headers['content-type']))) {
    return Buffer.from(JSON.stringify(req.body), 'utf8');
  }
  throw new Refused(jsonMediaType(headerValue(req.headers['content-type'])) ? 'request_unmapped' : 'unsupported_media_type');
}

function headerValue(v: string | string[] | undefined): string | null {
  if (v === undefined) return null;
  return Array.isArray(v) ? v.join(', ') : v;
}

/**
 * Express-style middleware: `(req, res, next)`. On ALLOW it removes the Plenipo headers from `req`, sets
 * `req.plenipo` and calls `next()`. The reservation is settled when the response finishes: 2xx commits,
 * 4xx releases (configurable on the gateway), anything else leaves it pending; `req.plenipo.settle()`
 * overrides the status. If the client goes away before the response finishes, the reservation stays
 * pending: the handler may still be executing the action.
 *
 * With `unmatched: 'pass'` on the gateway, requests that could reach a protected route under a different
 * letter case, trailing slash or method are refused, not passed. Prefer `plenipoRoute` on each protected
 * route, so Express's own routing decides which requests are checked.
 */
export function expressMiddleware(gateway: Gateway, opts: NodeAdapterOptions = {}): ExpressLikeMiddleware {
  const origin = opts.origin ?? 'http://localhost';
  const max = opts.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
  return (req, res, next) => {
    void (async () => {
      let body: Uint8Array | undefined;
      try {
        const refused = requestLineProblem(req, req.originalUrl ?? req.url);
        if (refused) throw new Refused(refused);
        body = await bodyFor(req, max);
      } catch (e) {
        if (e instanceof Refused) return writeFetchResponse(res, problemResponse(problemFromSpec(GATEWAY_PROBLEMS[e.problem])), req.method);
        throw e;
      }
      let request: Request;
      try {
        request = toFetchRequest(req, body, origin, req.originalUrl ?? req.url);
      } catch (e) {
        if (e instanceof TargetError) return writeFetchResponse(res, problemResponse(problemFromSpec(GATEWAY_PROBLEMS.malformed_target)), req.method);
        throw e;
      }
      const result = await gateway.authorize(request);
      if (result.kind === 'deny') return writeFetchResponse(res, result.response, req.method);
      if (result.kind === 'pass') return next();
      stripAuthorizationHeaders(req);
      let explicit = false;
      req.plenipo = {
        decision: result.decision,
        route: result.route,
        params: result.params,
        settle: async (outcome) => {
          explicit = true;
          await result.settle({ outcome: outcome === 'executed' ? 'commit' : outcome === 'not-executed' ? 'release' : 'pending' });
        },
      };
      res.once('finish', () => {
        if (!explicit) void result.settle({ status: res.statusCode });
      });
      res.once('close', () => {
        // Closed before finishing: the client went away or the handler failed mid-response. The handler may
        // still run the action, so nothing is released; the reservation waits for an explicit settle or the sweep.
        if (!res.writableFinished && !explicit) void result.settle({ outcome: 'pending' });
      });
      next();
    })().catch((e) => {
      opts.onError?.(e);
      if (!res.headersSent) void writeFetchResponse(res, problemResponse(problemFromSpec(GATEWAY_PROBLEMS.processing_error)), req.method);
    });
  };
}

/**
 * Middleware for one protected Express route: `app.post('/accounts/:account/payments', plenipoRoute(route,
 * gatewayOptions), handler)`. Express decides which requests reach it, so no request can bypass the check
 * through a routing difference; `route.path` must be the full path as the gateway sees it (including any
 * router mount prefix), otherwise every request is refused with 404.
 */
export function plenipoRoute(
  route: GatewayRoute,
  options: Omit<GatewayOptions, 'routes' | 'unmatched' | 'downstream'>,
  adapter: NodeAdapterOptions = {},
): ExpressLikeMiddleware {
  return expressMiddleware(createGateway({ ...options, routes: [route], unmatched: 'deny' }), adapter);
}
