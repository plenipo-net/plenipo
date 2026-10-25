/**
 * A deliberately small HTTP toolkit for the sandbox services: a router, bounded body parsing and
 * bounded outbound fetches. Everything that comes from the network is treated as hostile.
 */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';

export interface Request {
  raw: IncomingMessage;
  method: string;
  path: string;
  query: URLSearchParams;
  params: Record<string, string>;
  headers: IncomingMessage['headers'];
}

export type Handler = (req: Request, res: ServerResponse) => unknown | Promise<unknown>;

export class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

interface Route {
  method: string;
  parts: string[];
  handler: Handler;
}

export class Router {
  private readonly routes: Route[] = [];
  /** Requests whose path starts with one of these prefixes are passed whole to the handler. */
  private readonly mounts: Array<{ prefix: string; handler: Handler }> = [];

  get(path: string, h: Handler): this {
    return this.add('GET', path, h);
  }
  post(path: string, h: Handler): this {
    return this.add('POST', path, h);
  }
  mount(prefix: string, h: Handler): this {
    this.mounts.push({ prefix, handler: h });
    return this;
  }
  private add(method: string, path: string, handler: Handler): this {
    this.routes.push({ method, parts: path.split('/').filter(Boolean), handler });
    return this;
  }

  async handle(raw: IncomingMessage, res: ServerResponse): Promise<void> {
    let url: URL;
    try {
      url = new URL(raw.url ?? '/', 'http://sandbox.invalid');
    } catch {
      return sendJson(res, 400, { error: 'bad_request' });
    }
    const method = (raw.method ?? 'GET').toUpperCase();
    const req: Request = { raw, method, path: url.pathname, query: url.searchParams, params: {}, headers: raw.headers };
    try {
      for (const m of this.mounts) {
        if (url.pathname === m.prefix || url.pathname.startsWith(m.prefix + '/')) {
          await m.handler(req, res);
          return;
        }
      }
      const parts = url.pathname.split('/').filter(Boolean);
      let pathMatched = false;
      for (const r of this.routes) {
        const params = match(r.parts, parts);
        if (!params) continue;
        pathMatched = true;
        if (r.method !== method && !(r.method === 'GET' && method === 'HEAD')) continue;
        req.params = params;
        await r.handler(req, res);
        return;
      }
      sendJson(res, pathMatched ? 405 : 404, { error: pathMatched ? 'method_not_allowed' : 'not_found' });
    } catch (e) {
      if (res.headersSent) {
        res.end();
        return;
      }
      if (e instanceof HttpError) return sendJson(res, e.status, { error: e.message });
      // Internal errors are logged here and never echoed to the caller.
      console.error(`[http] ${method} ${url.pathname}:`, e);
      sendJson(res, 500, { error: 'internal_error' });
    }
  }
}

function match(pattern: string[], parts: string[]): Record<string, string> | null {
  if (pattern.length !== parts.length) return null;
  const params: Record<string, string> = {};
  for (let i = 0; i < pattern.length; i++) {
    if (pattern[i].startsWith(':')) {
      let v: string;
      try {
        v = decodeURIComponent(parts[i]);
      } catch {
        return null;
      }
      params[pattern[i].slice(1)] = v;
    } else if (pattern[i] !== parts[i]) return null;
  }
  return params;
}

const DEFAULT_BODY_LIMIT = 256 * 1024;

export async function readBody(req: Request, limit = DEFAULT_BODY_LIMIT): Promise<string> {
  const declared = Number(req.headers['content-length'] ?? '0');
  if (declared > limit) throw new HttpError(413, 'body_too_large');
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req.raw) {
    size += (chunk as Buffer).length;
    if (size > limit) throw new HttpError(413, 'body_too_large');
    chunks.push(chunk as Buffer);
  }
  return Buffer.concat(chunks).toString('utf8');
}

/** Parses a JSON or form-encoded body into a plain object of strings and values. */
export async function readFields(req: Request, limit = DEFAULT_BODY_LIMIT): Promise<Record<string, unknown>> {
  const text = await readBody(req, limit);
  const type = String(req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
  if (type === 'application/x-www-form-urlencoded') {
    return Object.fromEntries(new URLSearchParams(text));
  }
  if (text.trim() === '') return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new HttpError(400, 'invalid_json');
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) throw new HttpError(400, 'body_must_be_an_object');
  return parsed as Record<string, unknown>;
}

const SECURITY_HEADERS = {
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'no-referrer',
  'cache-control': 'no-store',
};

export function sendJson(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', ...SECURITY_HEADERS });
  res.end(JSON.stringify(body, null, 2));
}

export function sendText(res: ServerResponse, status: number, body: string, type = 'text/plain; charset=utf-8'): void {
  res.writeHead(status, { 'content-type': type, ...SECURITY_HEADERS });
  res.end(body);
}

export function sendHtml(res: ServerResponse, body: string, status = 200): void {
  res.writeHead(status, {
    'content-type': 'text/html; charset=utf-8',
    // Pages are self-contained: inline styles and scripts, nothing loaded from elsewhere.
    'content-security-policy': "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'",
    'x-frame-options': 'DENY',
    ...SECURITY_HEADERS,
  });
  res.end(body);
}

export function redirect(res: ServerResponse, location: string): void {
  res.writeHead(303, { location, ...SECURITY_HEADERS });
  res.end();
}

export interface RunningServer {
  server: Server;
  /** Base URL the server listens on, e.g. http://127.0.0.1:4003 */
  url: string;
  close(): Promise<void>;
}

export async function listen(router: Router, host: string, port: number): Promise<RunningServer> {
  // Mandate chains travel in headers on the REST API, so allow more than Node's 16 KB default.
  const server = createServer({ maxHeaderSize: 64 * 1024 }, (req, res) => void router.handle(req, res));
  server.requestTimeout = 30_000;
  server.headersTimeout = 10_000;
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => resolve());
  });
  const addr = server.address() as AddressInfo;
  const url = `http://${host}:${addr.port}`;
  return {
    server,
    url,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}

/** Requires `Authorization: Bearer <token>` when an admin token is configured. */
export function checkAdmin(req: Request, token: string | undefined): void {
  if (!token) return;
  const got = String(req.headers.authorization ?? '');
  if (got !== `Bearer ${token}`) throw new HttpError(401, 'admin_token_required');
}

export interface BoundedResponse {
  status: number;
  contentType: string;
  text: string;
}

/**
 * Outbound HTTP with a timeout, a size cap and no redirects, for anything whose URL came from
 * another party (request_uri, response_uri, status lists).
 */
export async function boundedFetch(
  url: string,
  init: RequestInit = {},
  limits: { timeoutMs?: number; maxBytes?: number } = {},
): Promise<BoundedResponse> {
  const u = new URL(url);
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error('only http and https URLs are fetched');
  const maxBytes = limits.maxBytes ?? 1_000_000;
  const res = await fetch(u, { ...init, redirect: 'error', signal: AbortSignal.timeout(limits.timeoutMs ?? 5_000) });
  const declared = Number(res.headers.get('content-length') ?? '0');
  if (declared > maxBytes) throw new Error('response is too large');
  const reader = res.body?.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  if (reader) {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) {
        await reader.cancel();
        throw new Error('response is too large');
      }
      chunks.push(value);
    }
  }
  return { status: res.status, contentType: res.headers.get('content-type') ?? '', text: Buffer.concat(chunks).toString('utf8') };
}

export function escapeHtml(s: unknown): string {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
