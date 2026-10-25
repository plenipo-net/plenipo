/**
 * Dashboard: polls the event log of every service over HTTP and streams the merged log to browsers
 * with Server-Sent Events. Agents may post narrative events (scenario titles, LLM messages) to it.
 */
import { randomUUID } from 'node:crypto';
import type { ServerResponse } from 'node:http';
import { EventLog, type SandboxEvent } from '../events.js';
import { boundedFetch, HttpError, listen, readFields, Router, sendHtml, sendJson, type RunningServer } from '../http.js';
import { DASHBOARD_HTML } from '../ui/dashboard-page.js';

export interface DashboardOptions {
  host: string;
  port: number;
  /** Services to poll: name → base URL. */
  sources: Record<string, string>;
  /** Links shown in the header, keyed by source name: a label and a URL a browser can open. */
  links: Record<string, { label: string; url: string }>;
  pollMs?: number;
}

export interface DashboardService extends RunningServer {
  agentEvents: EventLog;
  /** All events merged so far, in arrival order. */
  merged(): SandboxEvent[];
}

const MAX_MERGED = 10000;

export async function startDashboard(opts: DashboardOptions): Promise<DashboardService> {
  const agentEvents = new EventLog('agent');
  const merged: Array<SandboxEvent & { id: number }> = [];
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
  router.post('/api/agent-events', async (req, res) => {
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
    close: async () => {
      clearInterval(timer);
      for (const c of clients) c.end();
      await running.close();
    },
  };
}
