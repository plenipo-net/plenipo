/**
 * The front door of a hosted sandbox: one public port that dispatches by host name to the services,
 * for platforms that give a container a single port behind their TLS edge (Fly.io, Render, a VM with a
 * load balancer). `sandbox.example` goes to the dashboard, `wallet.sandbox.example` to the wallet, and
 * so on; `mcp.sandbox.example` to the hosted MCP gateway.
 *
 * Optional demo login: with `basicAuth` set, everything needs it except what a phone wallet, a remote
 * MCP client or a showcase page on another origin must reach without a browser login.
 */
import { createHash, timingSafeEqual } from 'node:crypto';
import { createServer, request, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';

export interface FrontOptions {
  host: string;
  port: number;
  /** Host name (lower case, no port) → internal base URL, e.g. { 'wallet.sandbox.example': 'http://127.0.0.1:4402' }. */
  routes: Record<string, string>;
  /** `user:password`. When set, every request outside `open` needs it. */
  basicAuth?: string;
  /** Requests that never need the demo login: host → path prefixes. */
  open?: Record<string, string[]>;
  /** Header the TLS edge sets with the client address, passed on as x-forwarded-for. */
  clientIpHeader?: string;
}

export interface RunningFront {
  server: Server;
  url: string;
  close(): Promise<void>;
}

/** What must stay reachable without the demo login, for a sandbox at `domain`. */
export function openPaths(domain: string): Record<string, string[]> {
  return {
    // The dashboard page is behind the login; the per-session feeds are read by a showcase elsewhere.
    [domain]: ['/api/demo/'],
    [`platform.${domain}`]: ['/request/', '/response/', '/status/'],
    [`pid.${domain}`]: ['/status/', '/trust-anchor.pem'],
    [`mcp.${domain}`]: ['/mcp', '/health'],
  };
}

/** The standard layout: the dashboard at the bare domain, one subdomain per service. */
export function hostRoutes(domain: string, urls: Record<string, string>): Record<string, string> {
  const r: Record<string, string> = { [domain]: urls.dashboard };
  for (const name of ['pid', 'wallet', 'platform', 'bank']) r[`${name}.${domain}`] = urls[name];
  if (urls.agent) r[`mcp.${domain}`] = urls.agent;
  return r;
}

const HOP_BY_HOP = ['connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade'];

const digest = (s: string) => createHash('sha256').update(s).digest();

export async function startFront(opts: FrontOptions): Promise<RunningFront> {
  const routes = new Map(Object.entries(opts.routes).map(([h, u]) => [h.toLowerCase(), new URL(u)]));
  const expected = opts.basicAuth ? digest(`Basic ${Buffer.from(opts.basicAuth).toString('base64')}`) : undefined;

  function isOpen(host: string, path: string): boolean {
    return (opts.open?.[host] ?? []).some((p) => path.startsWith(p));
  }

  function authorized(req: IncomingMessage): boolean {
    if (!expected) return true;
    const got = req.headers.authorization;
    return typeof got === 'string' && timingSafeEqual(digest(got), expected);
  }

  function fail(res: ServerResponse, status: number, text: string, headers: Record<string, string> = {}) {
    res.writeHead(status, { 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store', ...headers });
    res.end(text);
  }

  const server = createServer((req, res) => {
    // For the platform's health check, whatever host name it sends: every service must answer.
    if (req.url === '/healthz') {
      void Promise.all(
        [...new Set([...routes.values()].map((u) => u.origin))].map((o) =>
          fetch(o + '/', { method: 'HEAD', signal: AbortSignal.timeout(2000) }).then(
            () => true,
            () => false,
          ),
        ),
      ).then((up) => fail(res, up.every(Boolean) ? 200 : 503, up.every(Boolean) ? 'ok' : 'a service is down'));
      return;
    }
    const host = String(req.headers.host ?? '')
      .toLowerCase()
      .replace(/:\d+$/, '');
    const target = routes.get(host);
    if (!target) return fail(res, 404, 'unknown host');
    const path = (req.url ?? '/').split('?')[0];
    if (!isOpen(host, path) && !authorized(req)) {
      return fail(res, 401, 'demo login required', { 'www-authenticate': 'Basic realm="Plenipo sandbox", charset="UTF-8"' });
    }
    const headers = { ...req.headers };
    for (const h of HOP_BY_HOP) delete headers[h];
    // The services never see the demo login.
    delete headers.authorization;
    if (req.headers.authorization && isOpen(host, path)) headers.authorization = req.headers.authorization;
    const ip = opts.clientIpHeader ? req.headers[opts.clientIpHeader.toLowerCase()] : undefined;
    headers['x-forwarded-for'] = typeof ip === 'string' && ip ? ip : (req.socket.remoteAddress ?? '');
    headers['x-forwarded-proto'] = 'https';
    headers['x-forwarded-host'] = host;
    const up = request(
      { hostname: target.hostname, port: target.port, method: req.method, path: req.url, headers },
      (upRes) => {
        const out = { ...upRes.headers };
        for (const h of HOP_BY_HOP) delete out[h];
        res.writeHead(upRes.statusCode ?? 502, out);
        // Server-Sent Events and MCP streams go through as they come.
        res.flushHeaders();
        upRes.pipe(res);
      },
    );
    up.on('error', () => {
      if (!res.headersSent) fail(res, 502, 'service unavailable');
      else res.end();
    });
    res.on('close', () => up.destroy());
    req.pipe(up);
  });
  // Long-lived streams (dashboard feeds, MCP notifications) must not be cut by a request timeout.
  server.requestTimeout = 0;
  server.headersTimeout = 10_000;
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(opts.port, opts.host, () => resolve());
  });
  const addr = server.address() as AddressInfo;
  return {
    server,
    url: `http://${opts.host}:${addr.port}`,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}
