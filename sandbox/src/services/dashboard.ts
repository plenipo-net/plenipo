/**
 * Dashboard: polls the event log of every service over HTTP and streams the merged log to browsers
 * with Server-Sent Events. Agents may post narrative events (scenario titles, LLM messages) to it.
 *
 * Demo feeds: an agent event carrying a `demo_code` (the hosted MCP gateway tags every event of a
 * session with one) opens a feed for that code. The ids it mentions (request, mandate) are followed
 * through the other services' events, so the feed at /api/demo/<code> holds what happened to that one
 * session: the platform request, the wallet consent, the bank decisions, the payments. The feed is
 * public and readable cross-origin, for a showcase page hosted elsewhere.
 */
import { randomUUID } from 'node:crypto';
import type { ServerResponse } from 'node:http';
import { EventLog, type SandboxEvent } from '../events.js';
import { boundedFetch, checkAdmin, HttpError, listen, readFields, Router, sendHtml, sendJson, type RunningServer } from '../http.js';
import { DASHBOARD_HTML } from '../ui/dashboard-page.js';

export interface DashboardOptions {
  host: string;
  port: number;
  /** Services to poll: name → base URL. */
  sources: Record<string, string>;
  /** Links shown in the header, keyed by source name: a label and a URL a browser can open. */
  links: Record<string, { label: string; url: string }>;
  pollMs?: number;
  /** When set, posting agent events requires `Authorization: Bearer <token>`. */
  eventsToken?: string;
}

export interface DashboardService extends RunningServer {
  agentEvents: EventLog;
  /** All events merged so far, in arrival order. */
  merged(): SandboxEvent[];
  /** The events of one demo session, in arrival order. */
  demo(code: string): SandboxEvent[] | undefined;
}

const MAX_MERGED = 10000;
const MAX_DEMOS = 2000;
const MAX_DEMO_EVENTS = 1000;
/** How far back a new id is looked up, for events that reached the dashboard before the note naming it. */
const BACKFILL = 2000;
const DEMO_RE = /^[A-HJ-NP-Z2-9]{6}$/;

type Item = SandboxEvent & { id: number };

interface Demo {
  code: string;
  createdAt: string;
  ids: Set<string>;
  events: Item[];
  seen: Set<number>;
  clients: Set<ServerResponse>;
}

/** The mandate and request ids an event mentions. */
function idsOf(e: SandboxEvent): string[] {
  const out: string[] = [];
  const add = (v: unknown) => {
    if (typeof v === 'string' && v.length >= 8 && v.length <= 200) out.push(v);
  };
  for (const k of ['request_id', 'mandate_id', 'parent_id', 'leaf_mandate']) add(e[k]);
  for (const k of ['mandate_path', 'children']) if (Array.isArray(e[k])) for (const v of e[k] as unknown[]) add(v);
  if (Array.isArray(e.usage)) for (const u of e.usage as Array<{ mandate_id?: unknown }>) add(u?.mandate_id);
  return out;
}

const CORS = { 'access-control-allow-origin': '*', 'access-control-allow-methods': 'GET', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' };

export async function startDashboard(opts: DashboardOptions): Promise<DashboardService> {
  const agentEvents = new EventLog('agent');
  const merged: Item[] = [];
  const demos = new Map<string, Demo>();
  const idIndex = new Map<string, string>();
  /** Browsers watching a code whose session has not started yet. */
  const waiting = new Map<string, Set<ServerResponse>>();
  let watchers = 0;
  const cursors: Record<string, number> = Object.fromEntries(Object.keys(opts.sources).map((k) => [k, 0]));
  const health: Record<string, boolean> = {};
  const clients = new Set<ServerResponse>();
  let nextId = 0;
  // Lets open pages notice a restart: event ids start again from 1.
  const boot = randomUUID();

  function push(e: SandboxEvent) {
    const item = { ...e, id: ++nextId };
    merged.push(item);
    if (merged.length > MAX_MERGED) merged.splice(0, merged.length - MAX_MERGED);
    const line = `id: ${item.id}\ndata: ${JSON.stringify(item)}\n\n`;
    for (const c of clients) c.write(line);
    route(item);
  }

  function openDemo(code: string): Demo {
    let d = demos.get(code);
    if (d) return d;
    d = { code, createdAt: new Date().toISOString(), ids: new Set(), events: [], seen: new Set(), clients: waiting.get(code) ?? new Set() };
    waiting.delete(code);
    demos.set(code, d);
    if (demos.size > MAX_DEMOS) {
      const [oldest] = demos.values();
      for (const id of oldest.ids) idIndex.delete(id);
      for (const c of oldest.clients) c.end();
      demos.delete(oldest.code);
    }
    return d;
  }

  function addToDemo(d: Demo, item: Item) {
    if (d.seen.has(item.id) || d.events.length >= MAX_DEMO_EVENTS) return;
    d.seen.add(item.id);
    // Backfilled events are older than the last one: keep the feed in arrival order.
    let i = d.events.length;
    while (i > 0 && d.events[i - 1].id > item.id) i--;
    d.events.splice(i, 0, item);
    const line = `id: ${item.id}\ndata: ${JSON.stringify(item)}\n\n`;
    for (const c of d.clients) c.write(line);
  }

  function route(item: Item) {
    const tagged = typeof item.demo_code === 'string' && DEMO_RE.test(item.demo_code) ? item.demo_code : undefined;
    const ids = idsOf(item);
    let code = tagged;
    if (!code) for (const id of ids) if ((code = idIndex.get(id))) break;
    if (!code) return;
    const d = tagged ? openDemo(code) : demos.get(code);
    if (!d) return;
    // An id already followed by another session stays with it.
    const fresh = ids.filter((id) => !idIndex.has(id));
    for (const id of fresh) {
      idIndex.set(id, code);
      d.ids.add(id);
    }
    addToDemo(d, item);
    if (!fresh.length) return;
    const wanted = new Set(fresh);
    for (const old of merged.slice(-BACKFILL)) {
      if (old.id !== item.id && !d.seen.has(old.id) && idsOf(old).some((id) => wanted.has(id))) addToDemo(d, old);
    }
  }

  function demoCode(raw: string): string {
    const code = raw.toUpperCase();
    if (!DEMO_RE.test(code)) throw new HttpError(400, 'a demo code is six letters and digits');
    return code;
  }
  agentEvents.subscribe(push);

  let polling = false;
  async function poll() {
    if (polling) return;
    polling = true;
    try {
      await Promise.all(
        Object.entries(opts.sources).map(async ([name, base]) => {
          try {
            const res = await boundedFetch(`${base}/events?since=${cursors[name]}`, {}, { timeoutMs: 2000, maxBytes: 5_000_000 });
            if (res.status !== 200) throw new Error(String(res.status));
            const list = JSON.parse(res.text) as SandboxEvent[];
            for (const e of list) {
              if (e.seq > cursors[name]) {
                cursors[name] = e.seq;
                push(e);
              }
            }
            health[name] = true;
          } catch {
            health[name] = false;
          }
        }),
      );
    } finally {
      polling = false;
    }
  }
  const timer = setInterval(() => void poll(), opts.pollMs ?? 400);
  timer.unref();

  const router = new Router();
  router.get('/', (_req, res) => sendHtml(res, DASHBOARD_HTML));
  router.get('/api/config', (_req, res) => sendJson(res, 200, { links: opts.links, health, boot }));
  router.get('/api/events', (_req, res) => sendJson(res, 200, merged));
  router.get('/stream', (req, res) => {
    res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-store', connection: 'keep-alive' });
    const last = Number(req.headers['last-event-id'] ?? '0');
    for (const e of merged) if (e.id > last) res.write(`id: ${e.id}\ndata: ${JSON.stringify(e)}\n\n`);
    clients.add(res);
    const ping = setInterval(() => res.write(': ping\n\n'), 15000);
    req.raw.on('close', () => {
      clearInterval(ping);
      clients.delete(res);
    });
  });
  router.get('/demo/:code', (_req, res) => sendHtml(res, DASHBOARD_HTML));
  router.get('/api/demo/:code', (req, res) => {
    const code = demoCode(req.params.code);
    const d = demos.get(code);
    res.writeHead(200, { 'content-type': 'application/json; charset=utf-8', ...CORS });
    res.end(JSON.stringify({ code, known: Boolean(d), created_at: d?.createdAt ?? null, boot, events: d?.events ?? [] }));
  });
  router.get('/api/demo/:code/stream', (req, res) => {
    const code = demoCode(req.params.code);
    if (watchers >= 2000) throw new HttpError(503, 'too many watchers');
    const d = demos.get(code);
    res.writeHead(200, { 'content-type': 'text/event-stream', connection: 'keep-alive', ...CORS });
    const last = Number(req.headers['last-event-id'] ?? '0');
    res.write(`event: hello\ndata: ${JSON.stringify({ code, boot, known: Boolean(d) })}\n\n`);
    // A code may be watched before its session starts: the browser waits until the first event.
    let set: Set<ServerResponse>;
    if (d) {
      for (const e of d.events) if (e.id > last) res.write(`id: ${e.id}\ndata: ${JSON.stringify(e)}\n\n`);
      set = d.clients;
    } else {
      set = waiting.get(code) ?? new Set();
      waiting.set(code, set);
    }
    set.add(res);
    watchers++;
    const ping = setInterval(() => res.write(': ping\n\n'), 15000);
    req.raw.on('close', () => {
      clearInterval(ping);
      watchers--;
      // The set may have moved from waiting to the demo meanwhile: it is the same object.
      set.delete(res);
      if (!set.size && waiting.get(code) === set) waiting.delete(code);
    });
  });
  router.post('/api/agent-events', async (req, res) => {
    checkAdmin(req, opts.eventsToken);
    const body = await readFields(req, 64 * 1024);
    if (typeof body.type !== 'string' || !/^[a-z_]{1,40}$/.test(body.type)) throw new HttpError(400, 'invalid type');
    const { type, ...data } = body;
    sendJson(res, 201, agentEvents.append(type, data));
  });

  const running = await listen(router, opts.host, opts.port);
  return {
    ...running,
    agentEvents,
    merged: () => [...merged],
    demo: (code) => (demos.has(code) ? [...demos.get(code)!.events] : undefined),
    close: async () => {
      clearInterval(timer);
      for (const c of clients) c.end();
      for (const d of demos.values()) for (const c of d.clients) c.end();
      for (const set of waiting.values()) for (const c of set) c.end();
      await running.close();
    },
  };
}
