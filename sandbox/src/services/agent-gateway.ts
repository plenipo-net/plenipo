/**
 * The hosted MCP gateway: the Plenipo bridge served over Streamable HTTP, so that a remote MCP client
 * (Claude on the web, Claude Desktop with a remote connector) can use the sandbox without installing
 * anything.
 *
 * Every MCP session gets its own bridge. A mandate journey (agent key, pending request, mandate) gets a
 * demo code of six characters at its first request_mandate; the bridge tags its dashboard events with it,
 * and the dashboard serves the events of one code at /api/demo/<code>, so the person can watch it live.
 * The journey lives under its code, not under the connection: an MCP client may open several connections
 * for one conversation, and a later connection can take the journey over (mandate_status with demo_code).
 *
 * The same server runs the scripted scenarios on request (GET /scenarios, POST /scenarios/<id>/run),
 * each under a fresh demo code, for a showcase page that lets visitors trigger them and watch.
 *
 * Every request is recorded in the audit log (./mcp-audit.ts): initialize with the client's name, the
 * methods and tools called and their outcome, refusals, and requests to other paths. With an audit token
 * the log is readable at /admin/mcp-audit.
 *
 * Public exposure is bounded: an optional secret path token, a cap on open sessions, idle timeouts
 * (short for connections that never call a tool), a global rate of new sessions and a per-session rate of
 * requests. Remote MCP clients connect from their provider's servers, so the client address says little
 * about who is behind a session; it limits only the scenario runs, which come from visitors' browsers.
 */
import { createHash, randomInt, randomUUID, timingSafeEqual } from 'node:crypto';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import type { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import { SandboxAgentClient, type SandboxEndpoints } from '../agent/client.js';
import { BridgeCore, MemoryStateStore, type BridgeStateStore } from '../bridge/core.js';
import { BRIDGE_INSTRUCTIONS, createBridgeServer } from '../bridge/server.js';
import { HttpError, listen, readBody, Router, sendHtml, sendJson, sendText, type Request, type RunningServer } from '../http.js';
import { auditPage } from '../ui/audit-page.js';
import { clip, McpAudit, type Caller } from './mcp-audit.js';
import { runScenario, SCENARIOS, type ScenarioEnv } from '../scenarios.js';

export interface AgentGatewayOptions {
  host: string;
  port: number;
  platformUrl: string;
  /** The platform's public URL, for the links the bridge gives the person. */
  publicPlatformUrl?: string;
  bankUrl: string;
  /** Where the bridges post their events (the dashboard's internal URL). */
  dashboardUrl: string;
  dashboardToken?: string;
  /** Where a person watches a session: the demo code is appended as ?code=. Defaults to the dashboard feed. */
  watchUrl?: string;
  /** Public base URL of the dashboard, for the default watch link. */
  publicDashboardUrl?: string;
  token?: string;
  /** Open MCP sessions at most (default 500). */
  maxSessions?: number;
  /** Close a session that called a tool after this long without requests (default 2 hours). */
  idleSeconds?: number;
  /** Close a session that never called a tool after this long (default 10 minutes). */
  unusedIdleSeconds?: number;
  /** New MCP sessions per hour, all clients together (default 300). */
  sessionsPerHour?: number;
  /** Requests per minute on one MCP session (default 120). */
  requestsPerMinute?: number;
  clientIpHeader?: string;
  /** The bank's status cache, in seconds: how long a revocation takes to bite. */
  statusCacheSeconds?: number;
  log?: (line: string) => void;
  /** The audit log of the MCP endpoint. Default: in memory only. */
  audit?: McpAudit;
  /** Bearer token for /admin/mcp-audit. Without it the log is not served. */
  auditToken?: string;
  /** Lets visitors run the scripted scenarios. Each run gets its own client and demo code. */
  scenarios?: {
    endpoints: SandboxEndpoints;
    env: Omit<ScenarioEnv, 'client'>;
    /** Runs one address may start per hour (default 10); at most `concurrent` at once (default 3). */
    runsPerHour?: number;
    concurrent?: number;
  };
}

/** Scenarios that change state every session shares (the bank clock, a person's PID, the next transfer): not run on request. */
const PRIVATE_SCENARIOS = new Set(['expired', 'pid-revoked', 'retry-after-crash']);
export const PUBLIC_SCENARIOS = SCENARIOS.filter((s) => !PRIVATE_SCENARIOS.has(s.id));

export interface AgentGatewayService extends RunningServer {
  /** Path of the MCP endpoint, including the token when one is set. */
  mcpPath: string;
  /** Open sessions: id → demo code ('' until the session starts a journey). */
  sessions(): Map<string, string>;
  audit: McpAudit;
}

interface Session {
  core: BridgeCore;
  server: Server;
  transport: StreamableHTTPServerTransport;
  lastSeen: number;
  /** Whether the client ever called a tool on this session. */
  used: boolean;
  opened: number;
  caller: Caller;
}

/** How long a journey's state is kept for a later connection to take over. */
const JOURNEY_TTL_MS = 24 * 3600_000;
const MAX_JOURNEYS = 5000;

/** No 0/O or 1/I: the code is read aloud and typed by hand. */
const CODE_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
export const DEMO_CODE_RE = /^[A-HJ-NP-Z2-9]{6}$/;

export function newDemoCode(): string {
  let s = '';
  for (let i = 0; i < 6; i++) s += CODE_ALPHABET[randomInt(CODE_ALPHABET.length)];
  return s;
}

/** A fixed-window counter per key. */
class Limiter {
  private readonly hits = new Map<string, { start: number; n: number }>();
  constructor(
    private readonly max: number,
    private readonly windowMs: number,
  ) {}
  /** Counts a hit; false when the key is over its limit in the current window. */
  hit(key: string, now = Date.now()): boolean {
    const h = this.hits.get(key);
    if (!h || now - h.start >= this.windowMs) {
      this.hits.set(key, { start: now, n: 1 });
      return true;
    }
    h.n++;
    return h.n <= this.max;
  }
  sweep(now = Date.now()) {
    for (const [k, h] of this.hits) if (now - h.start >= this.windowMs) this.hits.delete(k);
  }
}

function rpcError(res: Parameters<Parameters<Router['mount']>[1]>[1], status: number, message: string, headers: Record<string, string> = {}) {
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store', ...headers });
  res.end(JSON.stringify({ jsonrpc: '2.0', error: { code: -32000, message }, id: null }));
}

export async function startAgentGateway(opts: AgentGatewayOptions): Promise<AgentGatewayService> {
  const log = opts.log ?? (() => {});
  const maxSessions = opts.maxSessions ?? 500;
  const idleMs = (opts.idleSeconds ?? 2 * 3600) * 1000;
  const unusedIdleMs = (opts.unusedIdleSeconds ?? 600) * 1000;
  const newSessions = new Limiter(opts.sessionsPerHour ?? 300, 3600_000);
  const requests = new Limiter(opts.requestsPerMinute ?? 120, 60_000);
  const sessions = new Map<string, Session>();
  const journeys = new Map<string, { store: BridgeStateStore; lastUsed: number }>();
  const mcpPath = opts.token ? `/mcp/${opts.token}` : '/mcp';
  const tokenBytes = opts.token ? Buffer.from(opts.token) : undefined;
  const audit = opts.audit ?? new McpAudit({ log });
  const auditDigest = opts.auditToken ? createHash('sha256').update(`Bearer ${opts.auditToken}`).digest() : undefined;
  /** Session ids are capabilities: the log keeps their first eight characters. */
  const short = (id: string | undefined) => (id ? id.slice(0, 8) : undefined);
  /** The endpoint path as logged: the token never appears. */
  const shownPath = (path: string) => (pathOk(path) ? '/mcp' : path.length > 120 ? `${path.slice(0, 120)}…` : path);
  const callerOf = (req: Request) => audit.caller(clientIp(req), req.headers['user-agent']);
  const reject = (req: Request, status: number, reason: string, sid?: string) =>
    audit.record({ ev: 'reject', status, reason, method: req.method, ...(sid ? { sid: short(sid) } : {}), ...callerOf(req) });

  const watchLink = (code: string) => {
    if (opts.watchUrl) return `${opts.watchUrl}${opts.watchUrl.includes('?') ? '&' : '?'}code=${code}`;
    return `${(opts.publicDashboardUrl ?? opts.dashboardUrl).replace(/\/$/, '')}/demo/${code}`;
  };

  function clientIp(req: Request): string {
    if (opts.clientIpHeader) {
      const v = req.headers[opts.clientIpHeader.toLowerCase()];
      if (typeof v === 'string' && v) return v.split(',')[0].trim();
    }
    return req.raw.socket.remoteAddress ?? 'unknown';
  }

  function pathOk(path: string): boolean {
    const rest = path.slice('/mcp'.length);
    if (!tokenBytes) return rest === '' || rest === '/';
    const got = Buffer.from(rest.replace(/^\//, '').replace(/\/$/, ''));
    return got.length === tokenBytes.length && timingSafeEqual(got, tokenBytes);
  }

  async function drop(id: string, why: string) {
    const s = sessions.get(id);
    if (!s) return;
    sessions.delete(id);
    audit.record({
      ev: 'session_closed',
      sid: short(id),
      reason: why,
      used: s.used,
      seconds: Math.round((Date.now() - s.opened) / 1000),
      ...(s.core.demoCode ? { demo: s.core.demoCode } : {}),
      ...s.caller,
    });
    // A connection that never acted leaves no trace in the public feeds.
    if (s.core.demoCode) await s.core.note('session_closed', { reason: why });
    await s.core.close();
    await s.transport.close().catch(() => {});
    await s.server.close().catch(() => {});
    log(`session ${id.slice(0, 8)}${s.core.demoCode ? ` (${s.core.demoCode})` : ''} closed (${why}${s.used ? '' : ', never used'})`);
  }

  const demo = {
    open() {
      let code = newDemoCode();
      while (journeys.has(code)) code = newDemoCode();
      const store = new MemoryStateStore();
      if (journeys.size >= MAX_JOURNEYS) journeys.delete(journeys.keys().next().value!);
      journeys.set(code, { store, lastUsed: Date.now() });
      log(`journey ${code} started`);
      return { code, store };
    },
    adopt(code: string) {
      const j = journeys.get(code);
      if (!j) return undefined;
      j.lastUsed = Date.now();
      return j.store;
    },
    watchUrl: watchLink,
  };

  async function open(ip: string, caller: Caller, init: { clientInfo?: { name?: unknown; version?: unknown }; protocolVersion?: unknown; capabilities?: unknown }): Promise<Session> {
    const tag = randomUUID().slice(0, 8);
    const core = new BridgeCore({
      platformUrl: opts.platformUrl,
      publicPlatformUrl: opts.publicPlatformUrl,
      bankUrl: opts.bankUrl,
      dashboardUrl: opts.dashboardUrl,
      dashboardToken: opts.dashboardToken,
      store: new MemoryStateStore(),
      log: (line) => log(`[${core.demoCode ?? tag}] ${line}`),
      demo,
      statusCacheSeconds: opts.statusCacheSeconds,
    });
    const session: Session = { core, server: undefined as never, transport: undefined as never, lastSeen: Date.now(), used: false, opened: Date.now(), caller };
    session.server = createBridgeServer(core, {
      instructions:
        `${BRIDGE_INSTRUCTIONS} This is the public Plenipo sandbox: the people, the bank and the money are simulated. ` +
        'The request_mandate answer carries a demo code and a link where the person can watch every step live: give both to the person.',
      onToolCall: (name) => {
        session.used = true;
        if (core.demoCode) {
          const j = journeys.get(core.demoCode);
          if (j) j.lastUsed = Date.now();
        }
        log(`[${core.demoCode ?? tag}] ${name}`);
      },
      onToolResult: (name, args, outcome) => {
        audit.record({
          ev: 'tool',
          sid: short(session.transport.sessionId),
          tool: clip(name, 80),
          // Names only: the values may hold what a person wrote.
          args: Object.keys(args).slice(0, 20),
          ...outcome,
          ...(core.demoCode ? { demo: core.demoCode } : {}),
          ...caller,
        });
      },
    });
    const server = session.server;
    session.transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      onsessioninitialized: (id) => {
        sessions.set(id, session);
        log(`session ${id.slice(0, 8)} opened from ${ip}`);
        const ci = init.clientInfo;
        audit.record({
          ev: 'initialize',
          sid: short(id),
          client: { name: clip(ci?.name, 80) ?? null, version: clip(ci?.version, 40) ?? null },
          protocol: clip(init.protocolVersion, 20),
          capabilities: init.capabilities && typeof init.capabilities === 'object' ? Object.keys(init.capabilities).slice(0, 10) : [],
          ...caller,
        });
      },
    });
    session.transport.onclose = () => {
      const id = session.transport.sessionId;
      if (id && sessions.get(id) === session) void drop(id, 'closed by the client');
    };
    await server.connect(session.transport);
    return session;
  }

  const CORS = { 'access-control-allow-origin': '*', 'cache-control': 'no-store', 'content-type': 'application/json; charset=utf-8' };
  const corsJson = (res: Parameters<Parameters<Router['get']>[1]>[1], status: number, body: unknown) => {
    res.writeHead(status, CORS);
    res.end(JSON.stringify(body));
  };
  const runs = new Limiter(opts.scenarios?.runsPerHour ?? 10, 3600_000);
  let activeRuns = 0;

  const router = new Router();
  router.get('/scenarios', (_req, res) => {
    if (!opts.scenarios) return corsJson(res, 404, { error: 'scenarios are not enabled here' });
    corsJson(res, 200, { scenarios: PUBLIC_SCENARIOS.map((s) => ({ id: s.id, title: s.title, expected: s.expected })) });
  });
  // A POST without a body is a simple cross-origin request: a showcase page calls it without a preflight.
  router.post('/scenarios/:id/run', async (req, res) => {
    const sc = opts.scenarios;
    if (!sc) return corsJson(res, 404, { error: 'scenarios are not enabled here' });
    const scenario = PUBLIC_SCENARIOS.find((s) => s.id === req.params.id);
    if (!scenario) return corsJson(res, 404, { error: 'unknown scenario' });
    if (activeRuns >= (sc.concurrent ?? 3)) return corsJson(res, 503, { error: 'busy: other scenarios are running, try again in a few seconds' });
    if (!runs.hit(clientIp(req))) return corsJson(res, 429, { error: 'too many runs from this address: try again later' });
    const code = newDemoCode();
    const client = new SandboxAgentClient({ ...sc.endpoints, noteFields: { demo_code: code } });
    activeRuns++;
    log(`scenario ${scenario.id} under ${code}`);
    void runScenario(scenario, { ...sc.env, client })
      .catch((e) => log(`scenario ${scenario.id} failed: ${(e as Error).message}`))
      .finally(() => {
        activeRuns--;
        void client.close();
      });
    corsJson(res, 202, { code, scenario: scenario.id, title: scenario.title, watch_url: watchLink(code) });
  });
  router.get('/health', (_req, res) => sendJson(res, 200, { ok: true, sessions: sessions.size }));

  // The audit log, for the owner of the sandbox. The page itself holds no data: it asks for the token.
  if (auditDigest) {
    const admin = (req: Request) => {
      const got = String(req.headers.authorization ?? '');
      if (!timingSafeEqual(createHash('sha256').update(got).digest(), auditDigest)) throw new HttpError(401, 'audit_token_required');
    };
    const num = (v: string | null) => (v && /^\d+$/.test(v) ? Number(v) : undefined);
    router.get('/admin/mcp-audit', (_req, res) => sendHtml(res, auditPage()));
    router.get('/admin/mcp-audit/summary', async (req, res) => {
      admin(req);
      sendJson(res, 200, await audit.summary({ from: req.query.get('from') ?? undefined, to: req.query.get('to') ?? undefined }));
    });
    router.get('/admin/mcp-audit/events', async (req, res) => {
      admin(req);
      sendJson(
        res,
        200,
        await audit.events({
          from: req.query.get('from') ?? undefined,
          to: req.query.get('to') ?? undefined,
          ev: req.query.get('ev') ?? undefined,
          sid: req.query.get('sid') ?? undefined,
          limit: num(req.query.get('limit')),
        }),
      );
    });
    router.get('/admin/mcp-audit/raw/:day', async (req, res) => {
      admin(req);
      const text = await audit.raw(req.params.day);
      if (text === undefined) throw new HttpError(404, 'no_log_for_this_day');
      sendText(res, 200, text, 'application/x-ndjson; charset=utf-8');
    });
  }
  // Anything else on this host: scanners, registries looking for other transports or OAuth metadata.
  router.onNotFound((req) => audit.record({ ev: 'probe', method: req.method, path: shownPath(req.path), ...callerOf(req) }));

  router.mount('/mcp', async (req, res) => {
    if (!pathOk(req.path)) {
      audit.record({ ev: 'probe', method: req.method, path: shownPath(req.path), ...callerOf(req) });
      throw new HttpError(404, 'not_found');
    }
    const ip = clientIp(req);
    const sid = req.headers['mcp-session-id'];
    const existing = typeof sid === 'string' ? sessions.get(sid) : undefined;
    if (typeof sid === 'string' && !existing) {
      reject(req, 404, 'unknown_session', sid);
      return rpcError(res, 404, 'Session not found: start a new one');
    }
    if (typeof sid === 'string' && !requests.hit(sid)) {
      reject(req, 429, 'session_rate_limit', sid);
      return rpcError(res, 429, 'Too many requests on this session: slow down', { 'retry-after': '60' });
    }

    if (req.method === 'POST') {
      let body: unknown;
      try {
        body = JSON.parse(await readBody(req, 1024 * 1024));
      } catch (e) {
        if (e instanceof HttpError) {
          reject(req, e.status, e.message);
          throw e;
        }
        reject(req, 400, 'invalid_json');
        return rpcError(res, 400, 'Parse error: the body must be JSON');
      }
      if (existing) {
        existing.lastSeen = Date.now();
        // Requests only (notifications carry no id); tool calls are recorded with their outcome.
        for (const m of Array.isArray(body) ? body : [body]) {
          const msg = m as { method?: unknown; id?: unknown } | null;
          if (!msg || typeof msg.method !== 'string' || msg.id === undefined || msg.method === 'tools/call') continue;
          audit.record({ ev: 'rpc', sid: short(sid as string), method: clip(msg.method, 60), ...existing.caller });
        }
        return existing.transport.handleRequest(req.raw, res, body);
      }
      if (!isInitializeRequest(body)) {
        const method = (body as { method?: unknown } | null)?.method;
        reject(req, 400, typeof method === 'string' ? `no_session:${clip(method, 40)}` : 'no_session');
        return rpcError(res, 400, 'Bad request: no session; send initialize first');
      }
      if (sessions.size >= maxSessions) {
        reject(req, 503, 'sessions_full');
        return rpcError(res, 503, 'The sandbox is full: try again in a few minutes', { 'retry-after': '300' });
      }
      if (!newSessions.hit('all')) {
        reject(req, 503, 'new_sessions_rate_limit');
        return rpcError(res, 503, 'The sandbox has taken too many new connections this hour: try again later', { 'retry-after': '600' });
      }
      const s = await open(ip, callerOf(req), (body as { params: Parameters<typeof open>[2] }).params ?? {});
      return s.transport.handleRequest(req.raw, res, body);
    }
    if (req.method === 'GET' || req.method === 'DELETE') {
      if (!existing) {
        reject(req, 400, 'no_session');
        return rpcError(res, 400, 'Bad request: mcp-session-id header required');
      }
      existing.lastSeen = Date.now();
      audit.record({ ev: 'stream', sid: short(sid as string), method: req.method, ...existing.caller });
      return existing.transport.handleRequest(req.raw, res);
    }
    reject(req, 405, 'method_not_allowed');
    return rpcError(res, 405, 'Method not allowed', { allow: 'GET, POST, DELETE' });
  });

  const timer = setInterval(() => {
    const now = Date.now();
    for (const [id, s] of sessions) if (now - s.lastSeen > (s.used ? idleMs : unusedIdleMs)) void drop(id, 'idle');
    for (const [code, j] of journeys) if (now - j.lastUsed > JOURNEY_TTL_MS) journeys.delete(code);
    newSessions.sweep(now);
    requests.sweep(now);
  }, 60_000);
  timer.unref();
  void audit.sweep();
  const auditTimer = setInterval(() => void audit.sweep(), 6 * 3600_000);
  auditTimer.unref();

  const running = await listen(router, opts.host, opts.port);
  // MCP GET streams stay open for server notifications: no request timeout on this server.
  running.server.requestTimeout = 0;
  return {
    ...running,
    mcpPath,
    sessions: () => new Map([...sessions].map(([id, s]) => [id, s.core.demoCode ?? ''])),
    audit,
    close: async () => {
      clearInterval(timer);
      clearInterval(auditTimer);
      // Sessions only: scenario runs end on their own and never outlive the services for long.
      for (const id of [...sessions.keys()]) await drop(id, 'shutdown');
      await running.close();
      await audit.flush();
    },
  };
}
